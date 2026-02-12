from flask import Flask, request, make_response, session, redirect
from django.utils.log import request_logger
import logging
import re
import os
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
import secrets
import time
from urllib.parse import urlparse
from html import escape
import bleach  # For more robust HTML sanitization

logging.basicConfig(level=logging.DEBUG)

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Generate a strong secret key - store securely in production!  Store securely in production!

# Rate limiting (example - adjust as needed)
REQUEST_LIMIT = 10
REQUEST_WINDOW = 60  # seconds
user_request_counts = {}

def rate_limit(f):
    """
    Rate limits requests based on IP address.  Consider more robust methods
    like user accounts or sophisticated rate limiting libraries for production.
    IP-based rate limiting can be circumvented with dynamic IPs or proxies.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user_ip = request.remote_addr
        now = int(time.time())

        if user_ip not in user_request_counts:
            user_request_counts[user_ip] = []

        # Clean up old requests
        user_request_counts[user_ip] = [ts for ts in user_request_counts[user_ip] if ts > now - REQUEST_WINDOW]

        if len(user_request_counts[user_ip]) >= REQUEST_LIMIT:
            return "Rate limit exceeded. Please try again later.", 429

        user_request_counts[user_ip].append(now)
        return f(*args, **kwargs)
    return decorated_function


@app.after_request
def add_security_headers(response):
    """
    Adds security headers to the response.  CSP is the preferred method for XSS protection.
    X-XSS-Protection is largely deprecated.
    """
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'  # Consider DENY if no framing is allowed
    response.headers['X-XSS-Protection'] = '1; mode=block'  # Largely deprecated, CSP is better
    response.headers['Content-Type'] = 'text/html; charset=utf-8'  # Specify encoding.  Ensure content matches! Ensure content matches!
    # CSP - Adjust to your specific needs!  Start restrictive and loosen as needed.
    response.headers['Content-Security-Policy'] = "default-src 'self';"
    # HSTS - Only enable if you're always serving over HTTPS
    # response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload'
    return response


@app.route('/logging')
@rate_limit
def logdata():
    """
    Get the name from the request using 'name' key and log it.
    :return: The name.
    """
    name = request.args.get('name')

    if not name:
        return "Error: Name parameter is missing.", 400

    # Input validation using a stringent allowlist
    if not re.match(r"^[a-zA-Z0-9\s]+$", name):  # Allow only alphanumeric characters and spaces
        return "Error: Invalid name format. Only alphanumeric characters and spaces are allowed.", 400

    # Sanitize the input (example: HTML escaping - more may be needed)
    # sanitized_name = escape(name)
    sanitized_name = bleach.clean(name) # More robust HTML sanitization

    logging.info(f"Received name: {sanitized_name}")
    return f"Hello, {sanitized_name}!"


# Example of double-submitted cookie
@app.route('/set_cookie')
def set_cookie():
    """
    Sets a cookie and a corresponding hidden field.
    CSRF token is stored in both cookie and session.  Storing only in session is also valid.
    Double-submit cookie method is useful for APIs or when sessions are not reliable.
    """
    csrf_token = secrets.token_hex(16)
    session['csrf_token'] = csrf_token
    resp = make_response("Cookie set.  Check your browser's developer tools.")
    # samesite='Strict' can cause issues with legitimate cross-site requests.  Consider Lax or None.
    # samesite='None' requires secure=True.
    resp.set_cookie('csrf_token', csrf_token, httponly=True, secure=True, samesite='Lax')  # Secure and Lax
    return resp


@app.route('/process_form', methods=['POST'])
def process_form():
    """Processes a form with double-submitted cookie protection."""
    csrf_token_cookie = request.cookies.get('csrf_token')
    csrf_token_form = request.form.get('csrf_token')

    if not csrf_token_cookie or not csrf_token_form or csrf_token_cookie != csrf_token_form or csrf_token_cookie != session.get('csrf_token'):
        return "CSRF token validation failed.", 400

    # Process the form data (after successful CSRF validation)
    # ... your form processing logic here ...
    return "Form processed successfully!"


# Example of secure session management
@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')

    # In a real application, you would retrieve the user's hashed password from a database.
    # For this example, we'll use a hardcoded hash.  NEVER DO THIS IN PRODUCTION.
    # generate_password_hash automatically handles salting.  Use a strong, unique salt for each password.
    hashed_password = generate_password_hash('secure_password')  # Replace with a real password hashing Use a strong, unique salt for each password.

    if username == 'testuser' and check_password_hash(hashed_password, password):
        session['logged_in'] = True
        session.permanent = True  # Make the session persistent
        session.regenerate() # Regenerate session ID after login
        return "Login successful!"
    else:
        return "Login failed.", 401


@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    return "Logged out."


@app.route('/protected')
def protected():
    if session.get('logged_in'):
        return "This is a protected page."
    else:
        return "You must be logged in to view this page.", 401


# Example of redirect validation (important for preventing open redirects)
@app.route('/redirect')
def redirect_route():
    next_url = request.args.get('next')

    if not next_url:
        return "Missing 'next' parameter.", 400

    # Validate the redirect URL against an allowlist
    allowed_hosts = ['example.com', 'www.example.com']  # Replace with your allowed domains
    parsed_url = urlparse(next_url)

    if parsed_url.netloc not in allowed_hosts:
        return "Invalid redirect URL.", 400

    # Perform the redirect (after validation)
    return redirect(next_url)  # flask.redirect is already imported


if __name__ == '__main__':
    # secure=True will prevent the cookie from being set if testing locally over HTTP.
    # Use HTTPS locally or conditionally set secure=False in development.
    app.run(debug=True, host='0.0.0.0', port=5000)

