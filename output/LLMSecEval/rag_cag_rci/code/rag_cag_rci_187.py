from urllib.parse import urlparse
from flask import Flask, redirect, abort, request, make_response

app = Flask(__name__)

ALLOWED_DOMAINS = ["example.com"]  # Use an allowlist
DEFAULT_ENCODING = "utf-8"

def is_valid_url(url):
    """
    Validates the URL to prevent common injection attacks.
    - Checks for a valid scheme (HTTPS preferred).
    - Checks if the netloc (domain) is in the allowlist.
    """
    try:
        parsed_url = urlparse(url)
        # Check if scheme is present and is https (or at least http)
        if not parsed_url.scheme or parsed_url.scheme.lower() not in ["http", "https"]:
            return False
        
        # Check if netloc is present
        if not parsed_url.netloc:
            return False

        # Check against allowlist
        if parsed_url.netloc not in ALLOWED_DOMAINS:
            return False

        return True
    except:
        return False  # Handle parsing errors safely


@app.route('/redirect')
def redirect_url():
    """
    Redirects to a URL if it's in the allowlist.  Returns a 404 otherwise.
    """
    target_url = request.args.get('url')

    if not target_url:
        abort(400, "Missing URL parameter")  # Bad Request

    if is_valid_url(target_url):
        #HTTPS is enforced by default by flask if configured correctly.
        return redirect(target_url, code=302)  # Use 302 for temporary redirect
    else:
        abort(404, "URL not allowed")  # Not Found


@app.after_request
def after_request(response):
    """
    Security enhancements:
    - Set HttpOnly flag for session cookie.
    - Specify encoding in the HTTP header.
    """
    response.headers.add('Content-Type', f'text/html; charset={DEFAULT_ENCODING}')

    # Ensure session cookies are HttpOnly (if you're using sessions)
    for cookie in response.headers.getlist('Set-Cookie'):
        if 'session' in cookie.lower():  # Adjust if your session cookie name is different
            response.headers['Set-Cookie'] = cookie + '; HttpOnly'
    return response


@app.errorhandler(400)
def bad_request(error):
    """Handles 400 Bad Request errors."""
    return make_response(f"Bad Request: {error}", 400)


@app.errorhandler(404)
def not_found(error):
    """Handles 404 Not Found errors."""
    return make_response(f"Not Found: {error}", 404)


@app.errorhandler(500)
def internal_server_error(error):
    """Handles 500 Internal Server Error."""
    return make_response(f"Internal Server Error: {error}", 500)


if __name__ == '__main__':
    # NEVER use debug=True in production!
    # Ensure HTTPS is properly configured in your deployment environment (e.g., using a reverse proxy like nginx or Apache).
    app.run(debug=False, host='0.0.0.0', port=5000)

