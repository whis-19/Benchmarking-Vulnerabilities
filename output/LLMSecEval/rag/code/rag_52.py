import re
import secrets
import urllib.parse
from flask import Flask, request, redirect, make_response, session

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)  # Generate a cryptographically strong secret key

# Regular expression to match URLs containing example.com
ALLOWED_HOST = r"^(example\.com)$"

def is_valid_url(url):
    """
    Validates the URL to prevent open redirect vulnerabilities.

    Args:
        url (str): The URL to validate.

    Returns:
        bool: True if the URL is valid, False otherwise.
    """
    try:
        parsed_url = urllib.parse.urlparse(url)

        # Check if the scheme is present and is either http or https
        if not parsed_url.scheme or parsed_url.scheme not in ("http", "https"):
            return False

        # Check if the netloc (hostname) is present
        if not parsed_url.netloc:
            return False

        # Validate the hostname against the ALLOWED_HOST regex
        if not re.match(ALLOWED_HOST, parsed_url.netloc):
            return False

        return True

    except Exception:
        # Handle any parsing errors as invalid URLs
        return False


@app.route('/')
def index():
    """
    The index route.  Returns a simple message.
    """
    return "Welcome to the redirector!"


@app.route('/redirect')
def redirect_route():
    """
    Redirects to the target URL if it's valid, otherwise redirects to /.
    """
    target = request.args.get('target')

    if not target:
        return redirect("/")

    if is_valid_url(target):
        response = make_response(redirect(target))
        response.headers['Content-Type'] = 'text/html; charset=utf-8'  # Specify encoding
        return response
    else:
        return redirect("/")


@app.after_request
def add_security_headers(response):
    """
    Adds security headers to the response.
    """
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    return response


if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)

