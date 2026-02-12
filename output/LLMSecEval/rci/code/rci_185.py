import re
from flask import Flask, request, redirect, abort
from urllib.parse import urlparse
import idna  # For IDN handling

app = Flask(__name__)

# More restrictive regex to match ONLY example.com and its subdomains
# This regex is still not perfect and domain whitelisting is preferred.
ALLOWED_DOMAIN = "example.com"
ALLOWED_URL_REGEX = r"^(https?://)?([a-zA-Z0-9-]+\.)*" + re.escape(ALLOWED_DOMAIN) + r"(/.*)?$"


def is_valid_url(url):
    """
    Validates the URL to prevent open redirect vulnerabilities.
    """
    try:
        result = urlparse(url)

        # Check if netloc (domain) is present and not empty
        if not result.netloc:
            return False

        # Check if scheme is present and is either http or https
        if not result.scheme or result.scheme not in ("http", "https"):
            return False

        # IDN Handling: Convert to Punycode for validation
        try:
            netloc = idna.encode(result.netloc).decode('ascii')  # Convert to ASCII
        except idna.IDNAError:
            return False  # Invalid IDN

        # Check if the domain ends with the allowed domain
        if not netloc.endswith(ALLOWED_DOMAIN):
            return False

        # Protocol Relative URL Check:  Disallow them
        if url.startswith('//'):
            return False

        # Regex Check (as a secondary check, but domain check is primary)
        if not re.match(ALLOWED_URL_REGEX, url):
            return False

        return True
    except:
        return False


@app.route("/")
def index():
    """
    Handles the root route.  Redirects to a default page or displays a message.
    """
    return "Welcome!  Use /redirect?target=<url> to redirect to a URL containing example.com."


@app.route("/redirect")
def redirect_to_target():
    """
    Redirects to the target URL if it matches the allowed regex.
    Otherwise, returns an error.
    """
    target = request.args.get("target")

    if not target:
        return "Error: No target URL provided.", 400  # Bad Request

    if is_valid_url(target):
        try:
            return redirect(target)
        except Exception as e:
            print(f"Error during redirect: {e}")  # Log the error
            return "Error: An unexpected error occurred during redirection.", 500  # Internal Server Error
    else:
        return "Error: Invalid target URL. The domain must end with example.com.", 400  # Bad Request


if __name__ == "__main__":
    # Never run this in production. Use a proper WSGI server.
    app.run(debug=True, host="0.0.0.0", port=5000)

