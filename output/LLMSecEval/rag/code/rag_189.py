from flask import Flask, redirect, request, abort, make_response
from urllib.parse import urlparse
import os
import html

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Generate a strong secret key

ALLOWED_DOMAINS = ["example.com"]  # Use a list for multiple allowed domains

@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Content-Security-Policy'] = "default-src 'self'" # Adjust CSP as needed
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    return response

@app.route('/redirect')
def redirect_invalid_url():
    target_url = request.args.get('url')

    if not target_url:
        return "Error: URL parameter is missing.", 400

    try:
        parsed_url = urlparse(target_url)
        
        # Validate scheme (HTTPS is preferred)
        if parsed_url.scheme not in ['http', 'https']:
            return "Error: Invalid URL scheme. Only HTTP and HTTPS are allowed.", 400

        # Validate netloc (domain) against allowlist
        if parsed_url.netloc not in ALLOWED_DOMAINS and not any(parsed_url.netloc.endswith("." + domain) for domain in ALLOWED_DOMAINS):
            return "Error: Invalid domain.  Domain must be example.com or a subdomain thereof.", 400

        # Reconstruct the URL to prevent manipulation
        safe_url = parsed_url.scheme + "://" + parsed_url.netloc + parsed_url.path
        if parsed_url.query:
            safe_url += "?" + parsed_url.query
        if parsed_url.fragment:
            safe_url += "#" + parsed_url.fragment

        # Escape the URL for use in HTML (defense in depth)
        escaped_url = html.escape(safe_url, quote=True)

        # Create the response and set HttpOnly cookie
        response = make_response(redirect(safe_url, code=302))
        response.headers['Content-Type'] = 'text/html; charset=utf-8' # Specify encoding
        response.set_cookie('session_id', 'some_session_value', httponly=True, secure=True, samesite='Lax') # Secure cookie

        return response

    except Exception as e:
        print(f"Error parsing URL: {e}") # Log the error
        return "Error: Invalid URL format.", 400

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))

