from flask import Flask, redirect, abort, request, make_response
from urllib.parse import urlparse
import re
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)  # Required for CSRF protection in Flask-WTF

# Strict allowlist for URL characters (alphanumeric, hyphen, underscore, period, slash)
ALLOWED_URL_CHARS = r"^[a-zA-Z0-9\-_\./:]+$"

def is_valid_url(url):
    """
    Validates the URL against a strict allowlist of characters and checks if it's from example.com.
    Handles arbitrary subdomains correctly.
    """
    if not re.match(ALLOWED_URL_CHARS, url):
        return False, "Invalid characters in URL."

    try:
        parsed_url = urlparse(url)
        if not parsed_url.netloc:
            return False, "Invalid URL: No network location (e.g., example.com) found."

        # Check if the netloc ends with "example.com" (allows for subdomains)
        if not parsed_url.netloc.endswith("example.com"):
            return False, "Invalid URL: Not from example.com."

        if parsed_url.scheme not in ['http', 'https']:
            return False, "Invalid URL: Scheme must be http or https."

        return True, None  # URL is valid

    except Exception as e:
        return False, f"Invalid URL: Could not parse URL. Error: {str(e)}"


@app.route('/redirect/<path:url>')
def redirect_invalid_url(url):
    """
    Redirects to the given URL if it's from example.com, otherwise returns an error.
    Uses a strict allowlist for URL characters and handles arbitrary subdomains.
    """

    # Validate request data (including URL)
    if request.method == 'POST':
        # Example: Validate a hidden field
        hidden_field = request.form.get('hidden_field')
        if hidden_field != 'expected_value':
            return "Invalid request: Hidden field validation failed.", 400

    is_valid, error_message = is_valid_url(url)

    if is_valid:
        # Properly encode the URL for redirection
        response = make_response(redirect(url, code=302))

        # Set HttpOnly flag for session cookie (if you're using sessions)
        # Example:  response.set_cookie('session', 'your_session_id', httponly=True)

        # Specify encoding in the HTTP header
        response.headers['Content-Type'] = 'text/html; charset=utf-8'

        return response
    else:
        return f"Invalid URL: {error_message}", 400


@app.errorhandler(400)
def bad_request(error):
    return f"Bad Request: {error}", 400

@app.errorhandler(404)
def not_found(error):
    return "Not Found", 404

@app.errorhandler(500)
def internal_server_error(error):
    return "Internal Server Error", 500


if __name__ == '__main__':
    #  Do NOT use debug=True in production.  It can expose sensitive information.
    app.run(debug=False, host='0.0.0.0', port=5000)

