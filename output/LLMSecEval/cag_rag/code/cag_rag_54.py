from urllib.parse import urlparse
from flask import Flask, redirect, abort, request, make_response

app = Flask(__name__)

ALLOWED_DOMAINS = {"example.com"}  # Use a set for faster lookups

def is_valid_url(url):
    """
    Validates the URL to prevent common injection attacks.
    - Checks for a valid scheme (HTTPS is preferred).
    - Checks if the domain is in the allowlist.
    """
    try:
        parsed_url = urlparse(url)
        # Check if scheme is present and is either http or https.  HTTPS is preferred.
        if not parsed_url.scheme or parsed_url.scheme.lower() not in ("http", "https"):
            return False
        
        # Check if netloc (network location) is present
        if not parsed_url.netloc:
            return False

        # Check if the domain is in the allowlist
        domain = parsed_url.netloc.lower()
        if domain not in ALLOWED_DOMAINS:
            return False

        return True

    except Exception:
        # Handle parsing errors gracefully.  Invalid URLs should not crash the application.
        return False

@app.route('/redirect')
def redirect_url():
    """
    Redirects to a URL if it's in the allowlist; otherwise, returns a 404.
    """
    target_url = request.args.get('url')

    if not target_url:
        return "URL parameter is missing", 400  # Bad Request

    if is_valid_url(target_url):
        response = make_response(redirect(target_url, code=302)) # Use 302 for temporary redirect
        response.headers['Content-Type'] = 'text/html; charset=utf-8' # Specify encoding
        response.headers['X-Content-Type-Options'] = 'nosniff' # Prevent MIME sniffing
        response.headers['X-Frame-Options'] = 'DENY' # Prevent clickjacking
        response.headers['Content-Security-Policy'] = "default-src 'self'" # Prevent XSS
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains' # Force HTTPS
        response.headers['Cache-Control'] = 'no-store' # Prevent caching
        response.headers['Pragma'] = 'no-cache' # Prevent caching
        response.headers['Expires'] = '0' # Prevent caching
        response.set_cookie('sessionid', 'dummyvalue', httponly=True, secure=True, samesite='Lax') # HttpOnly, Secure, and SameSite cookie
        return response
    else:
        abort(404)

@app.after_request
def add_security_headers(response):
    """
    Adds security headers to every response.
    """
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Cache-Control'] = 'no-store'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)

