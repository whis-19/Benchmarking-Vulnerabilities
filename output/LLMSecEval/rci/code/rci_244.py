import subprocess
import functools
from flask import Flask, request, jsonify
import re
import urllib.parse
import logging
import os
import ipaddress
import hashlib
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import idna

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Initialize rate limiter
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]  # Example limits
)


# Secure decorator to bind a function to a URL
def route(url):
    """
    Decorator to bind a function to a URL.

    Args:
        url (str): The URL to bind the function to.
    """
    def decorator(f):
        @app.route(url)
        @functools.wraps(f)  # Preserve original function's metadata
        @limiter.limit("10 per minute") # Example rate limit for each endpoint
        def wrapper(*args, **kwargs):
            return f(*args, **kwargs)
        return wrapper
    return decorator


def hash_url(url):
    """Hashes a URL using SHA256."""
    return hashlib.sha256(url.encode('utf-8')).hexdigest()


def normalize_idn(hostname):
    """Normalizes an IDN hostname."""
    try:
        return idna.encode(hostname).decode('ascii')
    except idna.IDNAError as e:
        logging.warning(f"IDNA normalization error: {e}")
        return None


def ping_host(hostname):
    """Pings a hostname using subprocess.run with explicit arguments."""
    try:
        result = subprocess.run(["ping", "-c", "1", hostname],
                                  capture_output=True,
                                  text=True,
                                  timeout=10)
        return result
    except subprocess.TimeoutExpired:
        return None


@route("/ping")
def ping():
    """
    Pings a URL and returns whether it is alive.
    """
    url = request.args.get("url")  # Get URL from request parameters

    if not url:
        logging.warning("Missing URL parameter")
        return jsonify({"error": "URL parameter is required"}), 400

    hashed_url = hash_url(url)

    # Input validation:  Sanitize the URL to prevent command injection
    # This is crucial for security.  A more robust solution might involve
    # a whitelist of allowed domains or more sophisticated parsing.
    if not is_valid_url(url):
        logging.warning(f"Invalid URL format: {hashed_url}")
        return jsonify({"error": "Invalid URL format"}), 400

    try:
        parsed_url = urllib.parse.urlparse(url)
        hostname = parsed_url.hostname or url  # Use the original URL if no scheme

        result = ping_host(hostname)

        if result is None:
            logging.warning(f"Ping timed out for {hashed_url}")
            return jsonify({"status": "timeout", "error": "Ping timed out"}), 504

        pong = result.stdout

        if result.returncode == 0:
            logging.info(f"Ping successful for {hashed_url}")
            return jsonify({"status": "alive", "output": pong})
        else:
            logging.warning(f"Ping failed for {hashed_url} with return code {result.returncode}")
            return jsonify({"status": "not alive", "output": pong, "error_code": result.returncode})

    except Exception as e:
        logging.exception(f"An unexpected error occurred while pinging {hashed_url}")
        return jsonify({"status": "error", "error": "An internal error occurred"}), 500


def is_valid_url(url):
    """
    More robust URL validation to prevent command injection and other issues.

    Args:
        url (str): The URL to validate.

    Returns:
        bool: True if the URL appears valid, False otherwise.
    """
    try:
        result = urllib.parse.urlparse(url)

        # Check for valid scheme (http, https)
        if result.scheme not in ("http", "https", ""): # Allow no scheme for hostnames
            logging.warning(f"Invalid scheme: {result.scheme}")
            return False

        # Check for hostname
        if not result.hostname and not re.match(r"^[a-zA-Z0-9.-]+$", url):
            logging.warning(f"Missing or invalid hostname: {url}")
            return False

        hostname = result.hostname or url # Use the original URL if no scheme

        # Basic hostname validation (more robust than the original regex)
        if hostname:
            if len(hostname) > 253:  # Maximum hostname length
                logging.warning(f"Hostname too long: {hostname}")
                return False
            if any(len(label) > 63 for label in hostname.split(".")): #Max label length
                logging.warning(f"Label too long in hostname: {hostname}")
                return False
            if any("xn--" in label for label in hostname.split(".")):
                normalized_hostname = normalize_idn(hostname)
                if normalized_hostname is None:
                    return False
                hostname = normalized_hostname

            # Check for internal hostnames (optional, depending on requirements)
            if hostname.endswith(".local"):
                logging.warning(f"Internal hostname detected: {hostname}")
                return False

        # Check for command injection characters (more comprehensive)
        if any(char in url for char in "&;`|><$(){}[]\\\"'"):
            logging.warning(f"Command injection characters detected in URL: {url}")
            return False

        # Check for IP address (basic validation)
        try:
            if result.hostname:
                ipaddress.ip_address(result.hostname)
                logging.info(f"IP address detected: {result.hostname}")
        except ValueError:
            pass # Not an IP address

        return True

    except Exception as e:
        logging.exception(f"Error during URL validation: {url}")
        return False


if __name__ == "__main__":
    # Determine the port to listen on
    port = int(os.environ.get("PORT", 5000))
    app.run(debug=False, host="0.0.0.0", port=port)

