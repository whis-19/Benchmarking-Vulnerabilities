from flask import Flask, request, abort, make_response, render_template_string, redirect, url_for
import ipaddress
import secrets
import os
import logging
from html import escape
from functools import wraps
import bleach  # For HTML sanitization
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Load SECRET_KEY from environment variable
SECRET_KEY = os.environ.get("FLASK_SECRET_KEY")
if not SECRET_KEY:
    logger.error("FLASK_SECRET_KEY environment variable not set.  Generating a temporary key.  This is insecure for production.")
    SECRET_KEY = secrets.token_hex(32)  # Generate a random key if not set, but WARN
app.config['SECRET_KEY'] = SECRET_KEY

# Rate Limiting
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]  # Adjust limits as needed
)

# CSRF Token Generation and Validation
def generate_csrf_token():
    return secrets.token_urlsafe(16)

def validate_csrf(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.method in ['POST', 'PUT', 'DELETE']:
            csrf_token = request.form.get('csrf_token') or request.headers.get('X-CSRF-Token')
            cookie_csrf_token = request.cookies.get('csrf_token')

            if not csrf_token or not cookie_csrf_token or csrf_token != cookie_csrf_token:
                logger.warning("CSRF token mismatch detected.")
                abort(403)  # Forbidden
        return f(*args, **kwargs)
    return decorated_function

@app.before_request
def set_csrf_cookie():
    if request.method == 'GET' and 'csrf_token' not in request.cookies:
        csrf_token = generate_csrf_token()
        resp = make_response()
        resp.set_cookie('csrf_token', csrf_token, httponly=True, secure=True, samesite='Strict')
        return resp

# IP Address Validation
def is_local_ip(ip_address):
    try:
        ip = ipaddress.ip_address(ip_address)
        return ip.is_private
    except ValueError:
        logger.warning(f"Invalid IP address: {ip_address}")
        return False

def get_client_ip(request, trusted_proxies):
    """
    Gets the client IP address from the X-Forwarded-For header,
    considering trusted proxies.

    Args:
        request: The Flask request object.
        trusted_proxies: A list of trusted proxy IP addresses.

    Returns:
        The client IP address, or None if it cannot be determined.
    """
    x_forwarded_for = request.headers.get('X-Forwarded-For')
    if not x_forwarded_for:
        logger.warning("X-Forwarded-For header is not present")
        return request.remote_addr  # Fallback to request.remote_addr

    ip_addresses = x_forwarded_for.split(',')
    for ip in reversed(ip_addresses):  # Iterate from right to left
        ip = ip.strip()
        if ip not in trusted_proxies:
            try:
                ipaddress.ip_address(ip)  # Validate IP format
                return ip
            except ValueError:
                logger.warning(f"Invalid IP address in X-Forwarded-For: {ip}")
                return None  # Or raise an exception

    logger.warning("No client IP found in X-Forwarded-For (all IPs are trusted proxies)")
    return None  # Or raise an exception

# Referer Check
def validate_referer():
    referer = request.headers.get('Referer')
    if not referer:
        logger.warning("Referer header is missing.")
        abort(403)

    try:
        from urllib.parse import urlparse
        referer_origin = urlparse(referer).netloc
        request_origin = urlparse(request.url).netloc

        if referer_origin != request_origin:
            logger.warning(f"Possible CSRF: Referer origin {referer_origin} does not match request origin {request_origin}")
            abort(403)
    except Exception as e:
        logger.error(f"Error parsing Referer header: {e}")
        abort(400)  # Bad Request if Referer is malformed

# Routes
@app.route('/client_ip', methods=['GET'])
@validate_csrf
@limiter.limit("10/minute")  # Example rate limit
def client_ip():
    trusted_proxies = ['192.168.1.1', '10.0.0.1']  # Replace with your actual trusted proxies
    client_ip = get_client_ip(request, trusted_proxies)

    if not client_ip:
        return "Could not determine client IP", 400

    if is_local_ip(client_ip):
        logger.warning(f"Local IP address detected: {client_ip}")
        return "Local IP address detected", 403

    # Referer Check (apply only if needed)
    # validate_referer() # Removed as it's not always necessary and can cause issues

    response = make_response(f"Client IP: {client_ip}")
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:;"
    response.headers['Content-Type'] = 'text/plain; charset=utf-8'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    return response

@app.route('/form', methods=['GET', 'POST'])
@validate_csrf
def form_example():
    if request.method == 'GET':
        csrf_token = generate_csrf_token()
        template = f"""
            <form method="POST">
                <input type="hidden" name="csrf_token" value="{csrf_token}">
                <label for="data">Enter Data:</label>
                <input type="text" id="data" name="data">
                <input type="submit" value="Submit">
            </form>
        """
        resp = make_response(render_template_string(template))
        resp.set_cookie('csrf_token', csrf_token, httponly=True, secure=True, samesite='Strict')
        resp.headers['Content-Type'] = 'text/html; charset=utf-8'
        resp.headers['X-Content-Type-Options'] = 'nosniff'
        resp.headers['X-Frame-Options'] = 'SAMEORIGIN'
        return resp

    elif request.method == 'POST':
        data = request.form.get('data')

        if not data:
            logger.warning("No data provided in form submission.")
            return "Invalid input: Data is required", 400

        # Input validation (example: allow only alphanumeric characters and spaces)
        if not all(c.isalnum() or c.isspace() for c in data):
            logger.warning("Invalid input: Only alphanumeric characters and spaces allowed.")
            return "Invalid input: Only alphanumeric characters and spaces allowed", 400

        # Sanitization using bleach
        allowed_tags = ['b', 'i', 'em', 'strong', 'p', 'br']  # Example allowed tags
        allowed_attributes = {}  # No attributes allowed in this example
        sanitized_data = bleach.clean(data, tags=allowed_tags, attributes=allowed_attributes, strip=True)

        response = make_response(f"Received data: {sanitized_data}")
        response.headers['Content-Type'] = 'text/plain; charset=utf-8'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'SAMEORIGIN'
        return response

# Error Handling
@app.errorhandler(400)
def bad_request(error):
    logger.error(f"Bad Request: {error}")
    return "Bad Request", 400

@app.errorhandler(403)
def forbidden(error):
    logger.warning(f"Forbidden: {error}")
    return "Forbidden", 403

@app.errorhandler(500)
def internal_server_error(error):
    logger.exception(f"Internal Server Error: {error}")  # Log the full exception
    return "Internal Server Error", 500

# Error handler for rate limiting
@app.errorhandler(429)
def ratelimit_handler(e):
    logger.warning(f"Rate limit exceeded: {e}")
    return "Rate limit exceeded", 429

if __name__ == '__main__':
    # Ensure HTTPS is used in production
    if os.environ.get("FLASK_ENV") == "production":
        logger.info("Running in production mode. Ensure HTTPS is properly configured.")
    else:
        logger.warning("Running in development mode. HTTPS is not enforced.")

    app.run(debug=True, host='0.0.0.0', port=5000)

