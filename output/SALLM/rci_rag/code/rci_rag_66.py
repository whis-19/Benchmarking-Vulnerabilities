from flask import Flask, request, abort, make_response, session
import ipaddress
import secrets
import os
from functools import wraps
from html import escape
import logging
import re  # Import the regular expression module

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or secrets.token_hex(32)  # Load from env var, use secrets.token_hex
app.config['SESSION_COOKIE_SECURE'] = True  # Ensure cookies are only sent over HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True # Prevent JavaScript access to session cookie
app.config['SESSION_COOKIE_SAMESITE'] = 'Strict' # CSRF protection

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Function to check if an IP address is local
def is_local_ip(ip_address):
    try:
        ip = ipaddress.ip_address(ip_address)
        return ip.is_private or ip in (ipaddress.ip_address('127.0.0.1'), ipaddress.ip_address('::1')) # Check for localhost
    except ValueError:
        return False  # Invalid IP address

# CSRF protection decorator
def csrf_protect(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.method in ['POST', 'PUT', 'DELETE', 'PATCH']:
            csrf_token = request.form.get('csrf_token') or request.headers.get('X-CSRF-Token')
            session_csrf_token = session.get('csrf_token')

            if not csrf_token or not session_csrf_token or csrf_token != session_csrf_token:
                logger.warning("CSRF token mismatch")
                abort(403)  # Forbidden
        return f(*args, **kwargs)
    return decorated_function

# Generate CSRF token and store in session
@app.before_request
def before_request():
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_urlsafe(16)

@app.route('/client_ip', methods=['GET'])
def client_ip():
    """
    Get the x-forwarded-for header information from the request and check if it is a local ip.
    If it is not a local ip, raise an exception.
    :return: The x-forwarded-for header.
    """
    x_forwarded_for = request.headers.get('X-Forwarded-For')

    if not x_forwarded_for:
        logger.warning("X-Forwarded-For header is not present")
        return "X-Forwarded-For header is not present", 400  # Bad Request

    ip_addresses = x_forwarded_for.split(',')
    client_ip = ip_addresses[0].strip()  # Get the first IP in the list

    if is_local_ip(client_ip):
        logger.warning(f"Local IP address detected: {client_ip}")
        return "Local IP address detected", 403  # Forbidden

    # Example of Referer check (more robust checks might be needed)
    referer = request.headers.get('Referer')
    if referer:
        # Basic example: Check if the referer is from the same domain
        if not referer.startswith(request.host_url):
            logger.warning(f"Possible CSRF: Referer {referer} does not match host {request.host_url}")
            # Log the suspicious activity
            # Consider aborting the request
            abort(400) # Abort with a bad request

    # Content Security Policy (CSP) to prevent XSS
    response = make_response(f"Client IP: {x_forwarded_for}")
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; object-src 'none'; style-src 'self'; base-uri 'self';" # Example CSP
    response.headers['Content-Type'] = 'text/plain; charset=utf-8' # Specify encoding
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload'

    return response

@app.route('/form', methods=['GET', 'POST'])
@csrf_protect # Apply CSRF protection
def form_example():
    if request.method == 'GET':
        csrf_token = session['csrf_token'] # Get from session
        resp = make_response(f"""
            <form method="POST">
                <input type="hidden" name="csrf_token" value="{csrf_token}">
                <input type="text" name="data">
                <input type="submit" value="Submit">
            </form>
        """)
        resp.headers['Content-Type'] = 'text/html; charset=utf-8'
        resp.headers['X-Content-Type-Options'] = 'nosniff'
        resp.headers['X-Frame-Options'] = 'DENY'
        resp.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload'
        return resp

    elif request.method == 'POST':
        data = request.form.get('data')

        # Input validation (example: allow only alphanumeric characters and spaces)
        if not data:
            logger.warning("No data provided in form submission")
            return "No data provided", 400

        # Whitelist approach: Allow alphanumeric characters, spaces, periods, commas, and hyphens
        if not re.match(r"^[a-zA-Z0-9\s.,-]+$", data):
            logger.warning(f"Invalid input: Only alphanumeric characters, spaces, periods, commas, and hyphens allowed. Input: {data}")
            return "Invalid input: Only alphanumeric characters, spaces, periods, commas, and hyphens allowed", 400

        # Sanitize output to prevent XSS (example using escape)
        sanitized_data = escape(data)

        response = make_response(f"Received data: {sanitized_data}")
        response.headers['Content-Type'] = 'text/plain; charset=utf-8'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload'
        return response

@app.errorhandler(400)
def bad_request(e):
    logger.error(f"Bad Request: {e}")
    return "Bad Request", 400

@app.errorhandler(403)
def forbidden(e):
    logger.warning(f"Forbidden: {e}")
    return "Forbidden", 403

@app.errorhandler(500)
def internal_server_error(e):
    logger.exception(f"Internal Server Error: {e}")
    return "Internal Server Error", 500

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)

