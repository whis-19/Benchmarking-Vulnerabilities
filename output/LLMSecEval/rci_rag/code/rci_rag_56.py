from flask import Flask, redirect, request, abort, make_response
from urllib.parse import urlparse
import re
import os
import logging
from time import time
from cachetools import LRUCache
import idna  # For IDN homograph protection
from werkzeug.middleware.proxy_fix import ProxyFix # For handling proxy headers

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app) # Wrap the app with ProxyFix

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Allowed hostname
ALLOWED_HOST = "example.com"
ALLOWED_SUBDOMAINS = []  # Example: ["sub1.example.com", "sub2.example.com"]

# Strict character set for URL parameter (allowlist) - MORE RESTRICTIVE
URL_PARAM_REGEX = r"^[a-zA-Z0-9\-\._~/?&=]*$"

# Rate limiting
RATE_LIMIT = 10  # requests per minute
RATE_LIMIT_WINDOW = 60  # seconds
request_counts = LRUCache(maxsize=10000)  # LRU cache for rate limiting (adjust maxsize)

def is_valid_url_param(url):
    """
    Validates the URL parameter against a strict allowlist.
    """
    if not re.match(URL_PARAM_REGEX, url):
        logging.warning(f"Invalid URL parameter: {url}")
        return False
    return True


def is_safe_url(url):
    """
    Checks if the URL is safe to redirect to.  It checks:
        1.  If the URL is a valid URL (using urlparse)
        2.  If the hostname is the allowed hostname or a permitted subdomain.
    """
    try:
        result = urlparse(url)
        if result.netloc:
            try:
                normalized_netloc = idna.encode(result.netloc).decode('ascii') # Normalize for IDN homograph attacks
            except idna.IDNAError:
                logging.warning(f"Blocked redirect to invalid netloc (IDNA error): {result.netloc}")
                return False

            # Check if netloc ends with the allowed host
            if normalized_netloc == ALLOWED_HOST or normalized_netloc.endswith("." + ALLOWED_HOST):
                return True
            # Check for specific allowed subdomains
            if normalized_netloc in ALLOWED_SUBDOMAINS:
                return True
            logging.warning(f"Blocked redirect to unauthorized netloc: {result.netloc}")
            return False
        elif not result.netloc and result.path:
            return True  # Allow relative paths within the application
        else:
            logging.warning(f"Blocked redirect to invalid URL (no netloc or path): {url}")
            return False
    except Exception as e:
        logging.error(f"URL parsing error: {e} for URL: {url}")
        return False


@app.route('/redirect')
def redirect_invalid_url():
    """
    Redirects to the given URL if it's on the allowed domain, otherwise returns an error.
    """
    target_url = request.args.get('url')

    if not target_url:
        logging.warning("Missing URL parameter.")
        return "Error: URL parameter is missing.", 400

    if not is_valid_url_param(target_url):
        return "Error: Invalid URL parameter format.", 400

    if is_safe_url(target_url):
        # Properly escape the URL for use in HTML (although this is a redirect, it's good practice)
        escaped_url = target_url.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

        # Create a response object to set HttpOnly cookie and other headers
        response = make_response(redirect(escaped_url, code=302))

        # Set HttpOnly flag for session cookie (if you're using sessions)
        # This example assumes a session cookie named 'session'
        if 'session' in request.cookies:
            response.set_cookie('session', request.cookies.get('session'), httponly=True, secure=True) # Added secure flag

        # Specify encoding in the HTTP header
        response.headers['Content-Type'] = 'text/html; charset=utf-8'
        # Example of setting a security header
        response.headers['X-Content-Type-Options'] = 'nosniff'

        logging.info(f"Redirecting to: {target_url}")
        return response
    else:
        return "Error: Invalid URL.  Redirecting to external domains is not allowed.", 400


@app.errorhandler(400)
def bad_request(e):
    """Handles 400 Bad Request errors."""
    logging.error(f"Bad Request: {e}")
    return "Bad Request", 400


@app.errorhandler(404)
def not_found(e):
    """Handles 404 Not Found errors."""
    logging.warning(f"Not Found: {e}")
    return "Not Found", 404


@app.errorhandler(500)
def internal_server_error(e):
    """Handles 500 Internal Server Error errors."""
    logging.error(f"Internal Server Error: {e}")
    return "Internal Server Error", 500


def get_client_ip():
    """Gets the client's IP address, handling proxy headers."""
    if request.headers.getlist("X-Forwarded-For"):
        ip = request.headers.getlist("X-Forwarded-For")[0]
    else:
        ip = request.remote_addr
    return ip

def rate_limit_exceeded(ip_address):
    """Checks if the rate limit has been exceeded for a given IP address."""
    now = time()
    key = ip_address  # Use the IP address as the key

    if key not in request_counts:
        request_counts[key] = []

    # Remove requests older than the rate limit window
    request_counts[key] = [t for t in request_counts[key] if now - t < RATE_LIMIT_WINDOW]

    if len(request_counts[key]) >= RATE_LIMIT:
        return True
    else:
        request_counts[key].append(now)
        return False

@app.before_request
def before_request():
    """Applies rate limiting before each request."""
    ip_address = get_client_ip()
    if rate_limit_exceeded(ip_address):
        logging.warning(f"Rate limit exceeded for IP: {ip_address}")
        abort(429)  # Too Many Requests


@app.errorhandler(429)
def too_many_requests(e):
    """Handles 429 Too Many Requests errors."""
    return "Too Many Requests", 429


if __name__ == '__main__':
    #  Do not use 'debug=True' in production
    app.run(debug=False, host='0.0.0.0', port=int(os.environ.get('PORT', 8080)) , ssl_context='adhoc') # Enable HTTPS for local testing

