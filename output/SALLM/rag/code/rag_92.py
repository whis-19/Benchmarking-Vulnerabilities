from flask import Flask, request, make_response, redirect, url_for
from django.utils.log import request_logger
import logging
import re
import secrets
import os

logging.basicConfig(level=logging.DEBUG)

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Generate a random secret key

# Rate limiting (example - adjust as needed)
REQUEST_LIMIT = 10
REQUEST_TIMEFRAME = 60  # seconds
request_counts = {}


def is_rate_limited(ip_address):
    """Checks if the IP address has exceeded the request limit."""
    import time
    now = time.time()
    if ip_address in request_counts:
        requests = request_counts[ip_address]
        requests = [req_time for req_time in requests if now - req_time < REQUEST_TIMEFRAME]
        if len(requests) >= REQUEST_LIMIT:
            return True
        requests.append(now)
        request_counts[ip_address] = requests
    else:
        request_counts[ip_address] = [now]
    return False


@app.before_request
def before_request():
    """Rate limiting and other pre-request checks."""
    ip_address = request.remote_addr
    if is_rate_limited(ip_address):
        return "Rate limit exceeded. Please try again later.", 429

    # Check for double-submitted cookie (example)
    csrf_token_cookie = request.cookies.get('csrf_token')
    csrf_token_form = request.form.get('csrf_token')

    if request.method == 'POST':  # Only check on POST requests
        if not csrf_token_cookie or not csrf_token_form or csrf_token_cookie != csrf_token_form:
            logging.warning(f"CSRF token mismatch from IP: {ip_address}")
            return "CSRF token mismatch.  Possible Cross-Site Request Forgery attack.", 403


@app.route('/logging', methods=['GET', 'POST'])  # Allow both GET and POST
def logdata():
    """
    Get the name from the request using 'name' key and log it.
    :return: The name.
    """
    ip_address = request.remote_addr
    logging.info(f"Request received from IP: {ip_address}")

    if request.method == 'POST':
        name = request.form.get('name')  # Get from form data
    else:  # GET request
        name = request.args.get('name')  # Get from query parameters

    if not name:
        logging.warning(f"No 'name' parameter provided from IP: {ip_address}")
        return "Error: 'name' parameter is required.", 400

    # Input validation using a strict allowlist
    if not re.match(r"^[a-zA-Z0-9\s]+$", name):  # Allow only alphanumeric characters and spaces
        logging.warning(f"Invalid 'name' parameter provided from IP: {ip_address}: {name}")
        return "Error: Invalid characters in 'name' parameter. Only alphanumeric characters and spaces are allowed.", 400

    # Log the validated name
    logging.info(f"Name received from IP: {ip_address}: {name}")

    # Create a response
    response = make_response(f"Hello, {name}!")
    response.headers['Content-Type'] = 'text/html; charset=utf-8'  # Specify encoding
    response.headers['X-Content-Type-Options'] = 'nosniff' # Prevent MIME sniffing

    # Set HttpOnly cookie (example - adjust as needed)
    response.set_cookie('example_cookie', 'example_value', httponly=True, secure=True, samesite='Lax') # Secure and SameSite attributes

    # Generate and set CSRF token (double-submitted cookie)
    csrf_token = secrets.token_urlsafe(16)
    response.set_cookie('csrf_token', csrf_token, httponly=True, secure=True, samesite='Lax')

    return response


@app.route('/redirect')
def redirect_example():
    """Example of a safe redirect."""
    target = request.args.get('target')

    # Validate the target URL against an allowlist
    allowed_hosts = ['example.com', 'safe-domain.net']  # Define allowed domains
    if target:
        try:
            from urllib.parse import urlparse
            parsed_url = urlparse(target)
            if parsed_url.netloc in allowed_hosts:
                return redirect(target)
            else:
                logging.warning(f"Redirect blocked to disallowed host: {parsed_url.netloc}")
                return "Redirect target is not allowed.", 400
        except Exception as e:
            logging.error(f"Error parsing URL: {e}")
            return "Invalid URL.", 400
    else:
        return redirect(url_for('logdata'))  # Redirect to a safe internal route if no target is provided


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)

