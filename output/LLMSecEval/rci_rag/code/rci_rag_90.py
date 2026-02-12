import os
import secrets
from flask import Flask, request, render_template, make_response, abort
import yaml
from markupsafe import escape
from cerberus import Validator
import logging  # Import the logging module

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(16)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


def generate_csrf_token():
    return secrets.token_hex(16)


def set_csrf_cookie(response):
    csrf_token = generate_csrf_token()
    response.set_cookie('csrf_token', csrf_token, httponly=True, secure=True,
                        samesite='Strict')  # Secure, HttpOnly, and SameSite
    return csrf_token


@app.route('/', methods=['GET', 'POST'])
# Example of very basic rate limiting (in-memory, not suitable for production)
request_counts = {}
RATE_LIMIT = 10  # requests per minute
RATE_LIMIT_WINDOW = 60  # seconds

def rate_limit_exceeded(ip_address):
    import time
    now = time.time()
    if ip_address not in request_counts:
        request_counts[ip_address] = []
    
    # Remove requests older than the rate limit window
    request_counts[ip_address] = [ts for ts in request_counts[ip_address] if now - ts < RATE_LIMIT_WINDOW]
    
    # Check if rate limit exceeded
    if len(request_counts[ip_address]) >= RATE_LIMIT:
        return True
    
    # Record the current request
    request_counts[ip_address].append(now)
    return False


@app.route('/', methods=['GET', 'POST'])
def index():
    ip_address = request.remote_addr  # Get the client's IP address

    if rate_limit_exceeded(ip_address):
        logger.warning(f"Rate limit exceeded for IP: {ip_address}")
        abort(429, "Too Many Requests")  # HTTP 429 Too Many Requests

    if request.method == 'GET':
        response = make_response(render_template('index.html', csrf_token=generate_csrf_token()))
        csrf_token = set_csrf_cookie(response)
        return response
    elif request.method == 'POST':
        # CSRF Protection: Verify Origin and Token
        # Referer check is removed for reliability reasons
        # referer = request.headers.get('Referer')
        # if not referer or not referer.startswith(request.url_root):
        #    abort(400, "Invalid Referer header")

        # Validate Content-Type
        if request.headers.get('Content-Type') != 'application/x-www-form-urlencoded':
            logger.warning(f"Invalid Content-Type header from IP: {ip_address}")
            abort(400, "Invalid Content-Type header")

        form_csrf_token = request.form.get('csrf_token')
        cookie_csrf_token = request.cookies.get('csrf_token')

        if not form_csrf_token or not cookie_csrf_token or form_csrf_token != cookie_csrf_token:
            logger.warning(f"CSRF token mismatch from IP: {ip_address}")
            abort(400, "CSRF token mismatch")

        payload = request.form.get('payload')

        if not payload:
            logger.warning(f"Missing payload parameter from IP: {ip_address}")
            return "Error: Payload parameter is missing", 400

        try:
            data = yaml.safe_load(payload)  # Use safe_load to prevent arbitrary code execution
        except yaml.YAMLError as e:
            logger.warning(f"Invalid YAML format from IP: {ip_address} - {e}")
            return f"Error: Invalid YAML format", 400  # Generic error message

        # Define a schema for the YAML data
        schema = {
            'type': {'type': 'string', 'required': True, 'allowed': ['Update', 'Delete']},  # Removed 'Create'
            'name': {'type': 'string', 'required': True, 'regex': '^[a-zA-Z0-9_]+$'},  # Example regex
            'description': {'type': 'string', 'required': False, 'maxlength': 200},  # Example maxlength
            'value': {'type': 'integer', 'required': False}
        }

        v = Validator(schema)
        if not v.validate(data):
            logger.warning(f"Invalid YAML data from IP: {ip_address} - {v.errors}")
            return f"Error: Invalid data", 400  # Generic error message

        # Removed the explicit 'Create' check as it's already handled by the schema

        logger.info(f"Payload processed successfully from IP: {ip_address} - {data}")
        return f"Payload processed successfully: {escape(str(data))}"  # Escape to prevent XSS
    return "Method not allowed", 405


@app.errorhandler(400)
def bad_request(error):
    logger.warning(f"Bad Request: {error}")
    return f"Bad Request", 400  # Generic error message


@app.errorhandler(429)
def too_many_requests(error):
    logger.warning(f"Too Many Requests: {error}")
    return "Too Many Requests", 429


if __name__ == '__main__':
    # Never run in production with debug=True
    app.run(debug=False, host='0.0.0.0', port=5000)

