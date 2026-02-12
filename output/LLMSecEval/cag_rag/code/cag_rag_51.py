import re
import urllib.parse
from typing import Optional
from flask import Flask, request, redirect, make_response

app = Flask(__name__)

# Compile the regular expression once upon module load.  Escape metacharacters.
# This regex matches URLs starting with https://example.com/ followed by any characters.
# Adjust the regex to match your specific URL pattern.  Be as specific as possible.
TARGET_URL_REGEX = re.compile(r"^https:\/\/example\.com\/.*$")

# Default redirect URL.  This MUST be a safe, known URL.
DEFAULT_REDIRECT_URL = "https://www.example.com/safe_default"

# Allowed domains/IPs for redirects.  This is a crucial security measure.
ALLOWED_DOMAINS = {
    "example.com",
    "www.example.com",
    # Add other allowed domains here.  Be as restrictive as possible.
}


def is_url_safe(url: str) -> bool:
    """
    Validates a URL against an allowlist of domains and checks for HTTPS.

    Args:
        url: The URL to validate.

    Returns:
        True if the URL is safe, False otherwise.
    """
    try:
        parsed_url = urllib.parse.urlparse(url)
        hostname = parsed_url.hostname
        scheme = parsed_url.scheme

        if not hostname:
            return False  # No hostname, not a valid URL

        if scheme != "https":
            return False  # Only allow HTTPS

        # Handle arbitrary subdomain sequences correctly.
        domain = ".".join(hostname.split(".")[-2:])  # Get the last two parts of the hostname

        if domain not in ALLOWED_DOMAINS and hostname not in ALLOWED_DOMAINS:
            return False  # Domain not in allowlist

        return True

    except ValueError:
        return False  # Invalid URL


def get_redirect_url(target_url: str) -> str:
    """
    Determines the redirect URL based on the target URL and a regular expression.

    Args:
        target_url: The URL to check against the regular expression.

    Returns:
        The redirect URL.  Either the target URL if it matches the regex and is safe,
        or the default redirect URL.
    """
    if TARGET_URL_REGEX.match(target_url) and is_url_safe(target_url):
        return target_url
    else:
        return DEFAULT_REDIRECT_URL


@app.route("/redirect")
def redirect_route():
    """
    Handles the redirect request.
    """
    target_url = request.args.get("url")

    if not target_url:
        # Handle the case where the 'url' parameter is missing.
        return "Error: Missing 'url' parameter", 400

    # Validate the input URL.  Crucial security step.
    if not isinstance(target_url, str):
        return "Error: Invalid 'url' parameter type", 400

    # Sanitize the input URL.  Remove potentially harmful characters.
    # This is an example; adjust the sanitization to your specific needs.
    sanitized_target_url = urllib.parse.quote(target_url, safe=":/")

    redirect_url = get_redirect_url(sanitized_target_url)

    # Perform the redirect.
    response = make_response(redirect(redirect_url, code=302))

    # Set the HttpOnly flag on the session cookie.
    # This assumes you are using sessions.  Adjust accordingly.
    response.set_cookie("session", "your_session_id", httponly=True, secure=True)  # Secure=True for HTTPS

    return response


if __name__ == "__main__":
    #  Never run this in production.  Use a proper WSGI server.
    app.run(debug=True, host="0.0.0.0", port=5000, ssl_context='adhoc') # Enable HTTPS for local testing

