from flask import request, redirect, Flask
import urllib.parse
import validators
import os
import idna  # For IDN handling
import tldextract # For more robust domain extraction
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import logging # For proper logging

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
app.logger.setLevel(logging.INFO)

# Configuration (ideally, load from environment variables)
ALLOWED_DOMAINS = os.environ.get("ALLOWED_DOMAINS", "").split(",")  # Comma-separated list, default to empty list
USE_HTTPS = os.environ.get("USE_HTTPS", "True").lower() == "true"  # Enforce HTTPS
DEBUG_MODE = os.environ.get("DEBUG", "False").lower() == "true" # Enable debug mode

# Rate Limiting
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)


def normalize_url(url):
    """Normalizes the URL for consistent validation.  Handles URL encoding and Unicode."""
    try:
        # Decode URL encoding
        url = urllib.parse.unquote(url)
        # Normalize Unicode representation (NFC)
        url = urllib.parse.quote(url.encode('utf-8', 'ignore').decode('utf-8', 'ignore')) # Re-encode to handle unicode
        return url
    except Exception as e:
        app.logger.error(f"Error normalizing URL: {e}") # Use proper logging
        return None

def is_valid_url(url):
    """
    Validates the URL using validators library and checks for common issues.
    """
    if not validators.url(url):
        return False

    parsed_url = urllib.parse.urlparse(url)

    # Check for javascript: or data: schemes (potential XSS)
    if parsed_url.scheme.lower() in ("javascript", "data"):
        return False

    # Check for relative URLs (can be dangerous if not handled carefully)
    if not parsed_url.netloc:  # No hostname means relative URL
        return False

    # Add length check
    if len(url) > 2048:
        return False

    return True


def is_allowed_domain(url, allowed_domains):
    """
    Checks if the domain of the URL is in the allowlist.
    """
    try:
        extracted = tldextract.extract(url)
        hostname = extracted.domain + "." + extracted.suffix
        return hostname in allowed_domains
    except Exception as e:
        app.logger.error(f"Error parsing URL: {e}")  # Log the error for debugging
        return False  # Default to denying if parsing fails


@app.route('/flask_redirect')
@limiter.limit("10/minute")  # Additional limit for the redirect endpoint
def flask_redirect():
    """
    Get the url from the request and redirect to it, with security checks.
    """
    target_url = request.args.get('url')

    if not target_url:
        return "Error: No URL provided.", 400

    normalized_url = normalize_url(target_url)
    if not normalized_url:
        return "Error: Invalid URL (Normalization Failed).", 400

    if not is_valid_url(normalized_url):
        return "Error: Invalid URL.", 400

    if not is_allowed_domain(normalized_url, ALLOWED_DOMAINS):
        return "Error: URL domain is not allowed.", 403

    # Enforce HTTPS (if configured)
    if USE_HTTPS:
        parsed_url = urllib.parse.urlparse(normalized_url)
        if parsed_url.scheme.lower() != "https":
            # Upgrade to HTTPS if possible.  If not, reject.
            secure_url = normalized_url.replace(parsed_url.scheme, "https", 1)
            # **CRITICAL**:  Check if the HTTPS version is valid *before* redirecting!
            if is_valid_url(secure_url) and is_allowed_domain(secure_url, ALLOWED_DOMAINS):
                # **CRITICAL**:  Also check if the HTTPS version *responds* before redirecting.  This requires making an HTTP request.
                #  This is complex and potentially slow, so consider carefully if it's necessary.
                #  A simple check would be:
                # try:
                #     import requests
                #     response = requests.head(secure_url, timeout=5) # Check if the server responds
                #     if response.status_code == 200:
                #         target_url = secure_url
                #     else:
                #         return "Error: HTTPS required, but the site is not responding.", 400
                # except requests.RequestException:
                #     return "Error: HTTPS required, but the site is unreachable.", 400
                target_url = secure_url # Redirect to the HTTPS version (after validation)
            else:
                return "Error: HTTPS required, and upgrade failed.", 400

    response = redirect(target_url, code=302)  # Use 302 for temporary redirect
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'none'; object-src 'none'; style-src 'self'"
    return response


if __name__ == '__main__':
    # DO NOT USE THIS IN PRODUCTION.  Use a proper WSGI server.
    # ssl_context='adhoc' generates a self-signed certificate, which is not trusted by browsers
    # and exposes users to man-in-the-middle attacks.  Use a valid SSL certificate from a trusted CA (e.g., Let's Encrypt).
    app.run(debug=DEBUG_MODE, host='0.0.0.0', port=5000, ssl_context='adhoc' if DEBUG_MODE and USE_HTTPS else None)

