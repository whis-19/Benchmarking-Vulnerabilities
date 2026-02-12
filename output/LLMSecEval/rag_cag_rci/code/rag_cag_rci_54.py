from urllib.parse import urlparse
from flask import Flask, redirect, abort, request, make_response

app = Flask(__name__)

ALLOWED_DOMAINS = ["example.com"]  # Use an allowlist
ALLOWED_SCHEMES = ["https"] # Only allow HTTPS

def is_valid_url(url):
    """
    Validates the URL against the allowlist and scheme.

    Args:
        url (str): The URL to validate.

    Returns:
        bool: True if the URL is valid, False otherwise.
    """
    try:
        parsed_url = urlparse(url)
        
        # Check scheme
        if parsed_url.scheme not in ALLOWED_SCHEMES:
            return False

        # Check netloc (domain) against allowlist
        if parsed_url.netloc not in ALLOWED_DOMAINS:
            return False

        return True
    except Exception:
        return False  # Handle parsing errors as invalid

def redirect_url(url):
    """
    Redirects to the given URL if it's in the allowlist.  Returns a 404 otherwise.

    Args:
        url (str): The URL to redirect to.

    Returns:
        flask.Response: A redirect response or a 404 error.
    """
    if not url:
        abort(400) # Or return a more informative error

    if is_valid_url(url):
        return redirect(url, code=302)  # Use 302 for temporary redirect
    else:
        abort(404)

@app.route("/redirect")
def handle_redirect():
    """
    Handles the redirect request.  Expects the URL to redirect to as a query parameter.
    """
    target_url = request.args.get("url")

    # Validate request data (including URL parameter)
    if not target_url:
        abort(400)  # Bad Request if URL is missing

    return redirect_url(target_url)

@app.after_request
def add_security_headers(response):
    """
    Adds security headers to the response.
    """
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Content-Security-Policy'] = "default-src 'self'" # Adjust CSP as needed
    return response

@app.route("/")
def index():
    """
    Simple index page.
    """
    return "Welcome!  Use /redirect?url=<target_url> to redirect."

if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=5000)

