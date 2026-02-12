import os
import re
from urllib.parse import urlparse
from flask import Flask, request, jsonify, redirect
from pythonping import ping  # Import python-ping
import tldextract
from dotenv import load_dotenv
import logging
import idna  # For IDN handling

load_dotenv()

app = Flask(__name__)

# Configuration from environment variables
ALLOWED_DOMAINS = [d.strip().lower() for d in os.environ.get("ALLOWED_DOMAINS", "example.com,example.net").split(",")]  # Lowercase for case-insensitive comparison and strip whitespace
USE_HTTPS = os.environ.get("USE_HTTPS", "True").lower() == "true"
PING_TIMEOUT = int(os.environ.get("PING_TIMEOUT", "5"))

# Regular expression for validating IP addresses
IP_ADDRESS_REGEX = r"^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Configure Flask to trust proxy headers
app.config['PREFERRED_URL_SCHEME'] = 'https'
# Adjust SECURE_PROXY_HEADERS based on your proxy configuration
app.config['SECURE_PROXY_HEADERS'] = {'X-Forwarded-Proto': 'https', 'X-Forwarded-For': '127.0.0.1'}


def is_valid_url(url: str) -> bool:
    """
    Validates the URL format and checks if it's an allowed domain or IP.
    Uses tldextract for accurate domain extraction and handles IDNs.

    Args:
        url: The URL to validate.

    Returns:
        True if the URL is valid, False otherwise.
    """
    try:
        result = urlparse(url)
        if not all([result.scheme, result.netloc]):
            return False

        hostname = result.hostname
        if hostname is None:
            return False

        # Check if it's an IP address
        if re.match(IP_ADDRESS_REGEX, hostname):
            logging.warning(f"Direct IP address not allowed: {hostname}")
            return False  # Reject direct IP addresses for now

        try:
            # Convert to Punycode for IDN handling
            hostname = idna.encode(hostname).decode('ascii')
        except idna.IDNAError:
            logging.warning(f"Invalid IDN hostname: {hostname}")
            return False

        # Use tldextract to get the registered domain
        ext = tldextract.extract(hostname)
        registered_domain = f"{ext.domain}.{ext.suffix}".lower()  # Lowercase

        # Check if the registered domain is in the allowlist
        if registered_domain not in ALLOWED_DOMAINS:
            logging.warning(f"Disallowed domain: {registered_domain}")
            return False

        return True

    except Exception as e:
        logging.exception(f"Error validating URL: {url}")
        return False


@app.route('/ping', methods=['GET'])
def ping_route():
    """
    Get the link from the request using 'link' and ping the link using python-ping.

    Returns:
        JSON response with the ping result or an error message.
    """
    link = request.args.get('link')

    if not link:
        return jsonify({"error": "Missing 'link' parameter"}), 400

    if not is_valid_url(link):
        return jsonify({"error": "Invalid or disallowed URL"}), 400

    try:
        # Extract hostname for pinging
        hostname = urlparse(link).hostname
        if not hostname:
            return jsonify({"error": "Invalid URL format"}), 400

        try:
            result = ping(hostname, count=3, timeout=PING_TIMEOUT)

            if result.success():
                return jsonify({"result": str(result)}), 200  # Or format the result as needed
            else:
                logging.error(f"Ping failed for {hostname}: {result}")
                return jsonify({"error": "Ping failed"}), 500  # Generic error message

        except OSError as e:
            logging.error(f"Error executing ping: {e}")
            return jsonify({"error": "Ping utility not found or inaccessible"}), 500
        except Exception as e:
            logging.exception(f"Unexpected error during ping: {e}")
            return jsonify({"error": "An unexpected error occurred during ping"}), 500


    except Exception as e:
        logging.exception(f"Error pinging {hostname}")
        return jsonify({"error": "An error occurred"}), 500  # Generic error message


# HTTPS enforcement with redirect
@app.before_request
def before_request():
    """
    Enforce HTTPS if USE_HTTPS is True by redirecting to HTTPS.
    """
    if USE_HTTPS and not request.is_secure:
        url = request.url.replace('http://', 'https://', 1)
        return redirect(url, code=301)  # 301 is a permanent redirect


if __name__ == '__main__':
    #  Never run this in production.  Use a proper WSGI server like gunicorn or uWSGI.
    #  Also, configure SSL/TLS properly for HTTPS.
    app.run(debug=True, host='0.0.0.0', port=5000)

