from flask import Flask, redirect, abort, request
from urllib.parse import urlparse, unquote
import tldextract
import idna
import os
import logging

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Load allowed domains from environment variable.  An empty list is a safer default.
ALLOWED_DOMAINS = os.environ.get("ALLOWED_DOMAINS", "").split(",")

def is_safe_url(url):
    """
    Checks if a URL is safe to redirect to, mitigating open redirect vulnerabilities.
    """
    try:
        # Remove fragment
        url = url.split('#')[0]

        decoded_url = unquote(url)
        result = urlparse(decoded_url)

        if result.scheme not in ("http", "https"):
            return False

        try:
            netloc = idna.encode(result.netloc).decode('ascii')  # Encode to Punycode
        except idna.IDNAError:
            return False  # Invalid IDN

        extracted = tldextract.extract(netloc)
        registered_domain = extracted.registered_domain

        if registered_domain.lower() not in [domain.lower() for domain in ALLOWED_DOMAINS]:
            return False

        return True

    except (ValueError, TypeError, UnicodeDecodeError) as e:
        app.logger.error(f"Error parsing URL: {url} - {e}")
        return False
    except Exception as e:
        app.logger.exception(f"Unexpected error checking URL: {url} - {e}", exc_info=True) # Log the full traceback
        return False


@app.route('/redirect/<path:url>')
def redirect_invalid_url(url):
    """
    Redirects to a URL if it's from an allowed domain. Otherwise, returns an error.
    """

    if is_safe_url(url):
        app.logger.info(f"Redirecting to safe URL: {url} from IP: {request.remote_addr}")  # Log successful redirect
        return redirect(url)
    else:
        app.logger.warning(f"Attempted redirect to unsafe URL: {url} from IP: {request.remote_addr}")
        abort(400, description="Invalid URL. Redirect blocked for security reasons.")


@app.errorhandler(400)
def bad_request(e):
    """
    Handles 400 Bad Request errors. Provides a more user-friendly error message.
    """
    return f"Bad Request: {e.description}", 400


if __name__ == '__main__':
    # Never run this in production with debug=True. It's a security risk.
    # Use a production WSGI server like gunicorn or uWSGI.
    app.run(debug=True, host='0.0.0.0', port=5000)

