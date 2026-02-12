import subprocess
import functools
from flask import Flask, request, jsonify
import os
import re
import socket
import logging
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
from logging.handlers import RotatingFileHandler

app = Flask(__name__)

# Configuration from environment variables with defaults
DEBUG = os.environ.get("DEBUG", "False").lower() == "true"
ALLOWED_HOSTS = os.environ.get("ALLOWED_HOSTS", "example.com,192.168.1.1").split(",")
DEFAULT_PING_TIMEOUT = 5  # Constant for default timeout
PING_TIMEOUT = int(os.environ.get("PING_TIMEOUT", str(DEFAULT_PING_TIMEOUT)))

# Logging setup
log_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
log_handler = RotatingFileHandler('ping_app.log', maxBytes=1024 * 1024, backupCount=5)  # Rotate logs
log_handler.setFormatter(log_formatter)

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
logger.addHandler(log_handler)

# Rate limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour", "10 per minute"],  # More granular
    storage_uri="memory://"  # Use a persistent storage for production
)

# Custom rate limit error message
@app.errorhandler(429)
def ratelimit_error(e):
    return jsonify({"error": "Too many requests. Please try again later."}), 429

# Security Headers
talisman = Talisman(
    app,
    content_security_policy={
        'default-src': '\'self\'',
        'script-src': '\'self\'',
        'style-src': '\'self\'',
        'img-src': '\'self\' data:',  # Restrict image sources further
        # 'report-uri': '/csp_report'  # Add a report URI to collect CSP violations
    },
    force_https=True,  # Only enable in production
    frame_options='DENY',
    x_content_type_options='nosniff',
    x_xss_protection='1; mode=block'
)


def route(url):
    """Decorator to bind a function to a URL."""

    def decorator(f):
        @app.route(url)
        @functools.wraps(f)
        def wrapper(*args, **kwargs):
            return f(*args, **kwargs)

        return wrapper

    return decorator


def is_valid_hostname(hostname):
    """
    Validates a hostname using a regular expression.
    This is a more robust check than a simple string comparison.
    """
    if not hostname:
        return False

    # Regex for validating a hostname (more comprehensive than a simple check)
    hostname_regex = re.compile(
        r"^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$"
    )
    return bool(hostname_regex.match(hostname))


def resolve_hostname(hostname):
    """Resolves a hostname to an IP address."""
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return None


@route("/ping")
@limiter.limit("10/minute")  # Rate limit the ping endpoint
def ping():
    """
    Pings the specified URL and returns the result.
    """
    url = request.args.get("url")

    if not url:
        logger.warning("Ping request missing URL parameter")
        return jsonify({"error": "URL parameter is required"}), 400

    # Input validation and sanitization
    if not is_valid_hostname(url):
        logger.warning(f"Invalid URL format: {url}")
        return jsonify({"error": "Invalid URL format"}), 400

    ip_address = resolve_hostname(url)
    if not ip_address:
        logger.warning(f"Could not resolve hostname: {url}")
        return jsonify({"error": "Could not resolve hostname"}), 400

    allowed_ips = [resolve_hostname(host) for host in ALLOWED_HOSTS if resolve_hostname(host)]
    if ip_address not in allowed_ips:
        logger.warning(f"IP address {ip_address} not in allowed list")
        return jsonify({"error": "URL not in allowed hosts list"}), 403

    # Resolve again immediately before the ping command
    ip_address_check = resolve_hostname(url)
    if ip_address_check != ip_address:
        logger.warning(f"DNS rebinding detected! IP address changed from {ip_address} to {ip_address_check}")
        return jsonify({"error": "DNS rebinding detected"}), 400

    try:
        # Construct the ping command.  Using -c 1 to limit to one ping.
        # Using -W to set a timeout.
        command = ["ping", "-c", "1", "-W", str(PING_TIMEOUT), ip_address]

        # Execute the command using subprocess.run with a timeout.
        # Capture stdout and stderr.
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=PING_TIMEOUT + 1,  # Add a small buffer to the timeout
            check=False,  # Don't raise an exception on non-zero exit code
        )

        # Check the return code.  A return code of 0 usually means success.
        if result.returncode == 0:
            logger.info(f"Ping successful to {url} ({ip_address})")
            return jsonify({"result": result.stdout})
        else:
            logger.error(f"Ping failed to {url} ({ip_address}): {result.stderr}")
            return jsonify({"error": "Ping failed"}, 500)

    except subprocess.TimeoutExpired:
        logger.warning(f"Ping timed out to {url} ({ip_address})")
        return jsonify({"error": "Ping timed out"}), 504  # Gateway Timeout
    except Exception as e:
        logger.exception(f"Error during ping to {url} ({ip_address})")
        return jsonify({"error": "An internal error occurred"}), 500


if __name__ == "__main__":
    app.run(debug=DEBUG, host="0.0.0.0")

