import re
import urllib.parse
from typing import Optional
from flask import Flask, request, redirect, make_response

app = Flask(__name__)

# Compile the regular expression once upon module load.  Escape metacharacters.
# This regex matches URLs starting with https://example.com/ followed by any characters.
# Example: https://example.com/path/to/resource
TARGET_URL_REGEX = re.compile(r"^https:\/\/example\.com\/.*$")

# Default redirect URL.  This should be a safe, known URL.
DEFAULT_REDIRECT_URL = "https://www.example.org/"

# Allowed domains.  This is a crucial security measure.
ALLOWED_DOMAINS = {"example.com", "www.example.org"}


def is_url_safe(url: str) -> bool:
    """
    Validates a URL against several security criteria:
    1.  Parses the URL to extract its components.
    2.  Checks if the scheme is HTTPS.
    3.  Checks if the hostname is in the allowlist.
    """
    try:
        parsed_url = urllib.parse.urlparse(url)
        if parsed_url.scheme != "https":
            return False  # Only allow HTTPS
        if parsed_url.hostname not in ALLOWED_DOMAINS:
            return False  # Hostname not in allowlist
        return True
    except ValueError:
        return False  # Invalid URL


def get_redirect_url(target_url: str) -> str:
    """
    Determines the redirect URL based on the target URL and the compiled regex.
    """
    if not isinstance(target_url, str):
        return DEFAULT_REDIRECT_URL  # Handle non-string input

    if TARGET_URL_REGEX.match(target_url):
        if is_url_safe(target_url):
            return target_url
        else:
            return DEFAULT_REDIRECT_URL
    else:
        return DEFAULT_REDIRECT_URL


@app.route("/redirect")
def redirect_route():
    """
    Handles the redirect logic.  Expects a 'target' parameter in the request.
    """
    target = request.args.get("target")

    if not target:
        # Handle missing target parameter.  Return a 400 Bad Request.
        return "Missing target parameter", 400

    redirect_url = get_redirect_url(target)

    # Perform a final check to ensure the redirect URL is safe before redirecting.
    if not is_url_safe(redirect_url):
        redirect_url = DEFAULT_REDIRECT_URL  # Fallback to default if unsafe

    response = make_response(redirect(redirect_url, code=302))

    # Set the HttpOnly flag on the session cookie.  This prevents client-side scripts from accessing the cookie.
    # This assumes you are using a session.  Adjust as needed for your session management.
    if 'session' in request.cookies:
        response.set_cookie('session', request.cookies.get('session'), httponly=True, secure=True, samesite='Lax') # Secure and SameSite attributes

    return response


if __name__ == "__main__":
    #  Never run this in production without a proper WSGI server (e.g., gunicorn, uWSGI).
    app.run(debug=True, host="0.0.0.0", port=5000, ssl_context='adhoc') # Enable HTTPS for local testing

