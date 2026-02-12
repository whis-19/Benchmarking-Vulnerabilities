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
import ipaddress
import time

app = Flask(__name__)

# Configuration from environment variables
DEBUG = os.environ.get("DEBUG", "False").lower() == "true"
ALLOWED_HOSTS = os.environ.get("ALLOWED_HOSTS", "127.0.0.1,192.168.1.1").split(",")
PING_TIMEOUT = int(os.environ.get("PING_TIMEOUT", "5"))

# Logging setup
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Rate limiting
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]  # Example limits - adjust as needed
)

# Security Headers
talisman = Talisman(
    app,
    content_security_policy={
        'default-src': '\'self\'',
        'script-src': '\'self\'',
        'style-src': '\'self\'',
        'img-src': '*'  # Adjust as needed if using external images
    },
    force_https=not DEBUG,  # Only force HTTPS in production
    frame_options='DENY',
    x_content_type_options='nosniff',
    x_xss_protection='1; mode=block'
)

# Hostname Cache (for DNS rebinding mitigation - use with caution)
hostname_cache = {}
hostname_cache_ttl = 60  # Cache for 60 seconds


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
    Validates a hostname using a regular expression and additional checks.
    """
    if not hostname:
        return False

    if len(hostname) > 253:  # Maximum hostname length
        return False

    if any(c in hostname for c in ["!", "@", "#", "$", "%", "^", "&", "*", "(", ")", "+", "=", "{", "}", "[", "]", "|", "\\", ";", "'", '"', "<", ">", "?"]):
        return False

    # Regex for validating a hostname (more comprehensive than a simple check)
    hostname_regex = re.compile(
        r"^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][a-zA-Z0-9\-]*[A-Za-z0-9])$"
    )
    return bool(hostname_regex.match(hostname))


def is_valid_ip_address(ip_address):
    """Validates an IP address."""
    try:
        ipaddress.ip_address(ip_address)
        return True
    except ValueError:
        return False


def resolve_hostname_cached(hostname):
    """Resolves a hostname to an IP address, using a cache."""
    now = time.time()
    if hostname in hostname_cache and hostname_cache[hostname]["expiry"] > now:
        return hostname_cache[hostname]["ip"]

    try:
        ip_address = socket.gethostbyname(hostname)
        hostname_cache[hostname] = {"ip": ip_address, "expiry": now + hostname_cache_ttl}
        return ip_address
    except socket.gaierror:
        return None


@route("/ping")
@limiter.limit("5/minute")  # Rate limit the ping endpoint - adjust as needed
def ping():
    """
    Pings the specified URL and returns the result.
    """
    url = request.args.get("url")

    if not url:
        logger.warning("Ping request missing URL parameter")
        return jsonify({"error": "URL parameter is required"}), 400

    if not is_valid_hostname(url):
        logger.warning(f"Invalid URL format: {url}")
        return jsonify({"error": "Invalid URL format"}), 400

    # Resolve hostname to IP address (using cache)
    ip_address = resolve_hostname_cached(url)
    if not ip_address:
        logger.warning(f"Could not resolve hostname: {url}")
        return jsonify({"error": "Could not resolve hostname"}), 400

    # Validate IP address
    if not is_valid_ip_address(ip_address):
        logger.warning(f"Invalid IP address: {ip_address}")
        return jsonify({"error": "Invalid IP address"}), 400

    # Use cached resolution for ALLOWED_HOSTS check
    allowed_ips = [resolve_hostname_cached(host) for host in ALLOWED_HOSTS if resolve_hostname_cached(host)]
    if ip_address not in allowed_ips:
        logger.warning(f"IP address {ip_address} not in allowed list for {url}")
        return jsonify({"error": "IP address not in allowed list"}), 403

    try:
        command = ["ping", "-c", "1", "-W", str(PING_TIMEOUT), ip_address]

        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=PING_TIMEOUT + 1,
            check=False,
        )

        if result.returncode == 0:
            logger.info(f"Ping successful to {url} ({ip_address})")
            return jsonify({"result": result.stdout})
        else:
            logger.error(f"Ping failed to {url} ({ip_address}): {result.stderr}")
            return jsonify({"error": "Ping failed"}, 500)

    except subprocess.TimeoutExpired:
        logger.warning(f"Ping timed out to {url} ({ip_address})")
        return jsonify({"error": "Ping timed out"}), 504
    except Exception as e:
        logger.exception(f"Error during ping to {url} ({ip_address}): {type(e).__name__} - {str(e)}")  # Log exception type and message
        return jsonify({"error": "An internal error occurred"}), 500


if __name__ == "__main__":
    # Document the need to configure rate limits appropriately.
    # Document the considerations for setting PING_TIMEOUT.
    app.run(debug=DEBUG, host="0.0.0.0")

