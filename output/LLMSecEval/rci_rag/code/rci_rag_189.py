from flask import Flask, redirect, request, abort, make_response
from urllib.parse import urlparse
import re
import os
import logging
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Allowed hostname
ALLOWED_HOST = "example.com"

# Strict allowlist for URL parameter characters (alphanumeric, hyphen, underscore, period, slash)
URL_PARAM_ALLOWLIST = r"^[a-zA-Z0-9\-_./]+$"

# Initialize rate limiter
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day, 50 per hour"],  # Adjust limits as needed
    storage_uri="memory://"  # Use a persistent storage for production - CHANGE THIS IN PRODUCTION!
)


def is_valid_url_parameter(url_param):
    """
    Validates the URL parameter against a strict allowlist.
    """
    if not re.match(URL_PARAM_ALLOWLIST, url_param):
        logging.warning(f"Invalid URL parameter detected: {url_param}")  # Log invalid URL attempts
        return False
    return True


def redirect_invalid_url(url):
    """
    Redirects to the given URL if it's a valid URL for example.com, otherwise returns an error.
    """

    if not is_valid_url_parameter(url):
        return "Error: The URL contains disallowed characters. Only alphanumeric characters, hyphens, underscores, periods, and slashes are allowed.", 400

    try:
        parsed_url = urlparse(url)
    except:
        logging.warning(f"Failed to parse URL: {url}") # Log parsing failures
        return "Error: Invalid URL format.", 400

    if not parsed_url.netloc:
        return "Error: URL must be absolute and include a domain.", 400

    # Handle arbitrary subdomains correctly.  Check if the *base* domain is allowed.
    hostname = parsed_url.netloc
    if hostname == ALLOWED_HOST or hostname.endswith("." + ALLOWED_HOST):
        # Properly construct the full URL for redirection.
        full_url = parsed_url.scheme + "://" + parsed_url.netloc + parsed_url.path
        if parsed_url.query:
            full_url += "?" + parsed_url.query
        if parsed_url.fragment:
            full_url += "#" + parsed_url.fragment

        return redirect(full_url, code=302)  # Use 302 for temporary redirect
    else:
        logging.warning(f"Invalid domain: {hostname}") # Log invalid domain attempts
        return "Error: Invalid domain.  Only URLs from example.com and its subdomains are allowed.", 400


@app.route('/redirect')
@limiter.limit("5/minute")  # Apply rate limiting to the redirect endpoint
def redirect_route():
    """
    Route that takes a URL parameter and redirects if valid.
    """
    url = request.args.get('url')

    if not url:
        return "Error: URL parameter is missing.", 400

    return redirect_invalid_url(url)


@app.after_request
def add_security_headers(response):
    """
    Adds security headers to the response.
    """
    response.headers['Content-Type'] = 'text/html; charset=utf-8'  # Specify encoding
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Cache-Control'] = 'no-store, must-revalidate' # Added must-revalidate
    response.headers['Pragma'] = 'no-cache'
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self';"  # Restrict content sources.  Adjust as needed!
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'

    return response


@app.route('/set_cookie')
def set_cookie():
    """
    Sets a HttpOnly cookie.
    """
    resp = make_response("Cookie set")
    resp.set_cookie('session_id', '12345', httponly=True, secure=True, samesite='Lax') # Secure and SameSite
    return resp


if __name__ == '__main__':
    # Use a secure, production-ready WSGI server like gunicorn or uWSGI in a real deployment.
    # This development server is for testing purposes only.
    app.run(debug=True, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))

