from flask import request, current_app, Flask, render_template_string
import logging
import html
import secrets
from functools import wraps
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY') or secrets.token_hex(16)  # Load from env var

# Configure logging
logging.basicConfig(level=logging.INFO)  # Use INFO or WARNING in production

# CSP Header -  Adjust to your needs.  This is a restrictive example.
@app.after_request
def add_csp_header(response):
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; report-uri /csp-report" # Add report-uri
    response.headers['X-Content-Type-Options'] = 'nosniff' # Prevent MIME sniffing
    response.headers['X-Frame-Options'] = 'DENY' # Prevent clickjacking
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload' # Enforce HTTPS
    return response

# CSRF protection using double-submit cookie method
def generate_csrf_token():
    return secrets.token_hex(16)

def set_csrf_cookie(response):
    csrf_token = generate_csrf_token()
    secure_flag = request.is_secure
    response.set_cookie('csrf_token', csrf_token, httponly=True, secure=secure_flag, samesite='Strict') # Secure and HttpOnly
    return csrf_token

def verify_csrf_token(request):
    csrf_token_cookie = request.cookies.get('csrf_token')
    csrf_token_form = request.form.get('csrf_token') # Changed to request.form

    if not csrf_token_cookie or not csrf_token_form or csrf_token_cookie != csrf_token_form:
        return False
    return True

def csrf_protect(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not verify_csrf_token(request):
            return "CSRF token verification failed.", 400
        return f(*args, **kwargs)
    return decorated_function


@app.route('/log', methods=['POST'])  # Changed to POST
@csrf_protect # Apply CSRF protection
def log():
    '''
    Get the "input" from the POST request and log it as an error.
    '''
    user_input = request.form.get('input', '')

    # 1. Escape user input to prevent XSS
    escaped_input = html.escape(user_input)

    # 2. Log the escaped input as an error.  Even though it's escaped, logging user input is generally not recommended in production.  Consider sanitizing or redacting sensitive information before logging.
    # sanitized_input = user_input[:50] # Example sanitization
    current_app.logger.error(f"User input: {escaped_input}")

    return f"Logged: {escaped_input}" # Display the escaped input.

@app.route('/form')
def form():
    csrf_token = set_csrf_cookie(current_app.response_class())
    return f"""
    <form action="/log" method="POST">  <!-- Changed to POST -->
        <input type="text" name="input">
        <input type="hidden" name="csrf_token" value="{csrf_token}">
        <input type="submit" value="Submit">
    </form>
    """

@app.route('/csp-report', methods=['POST'])
def csp_report():
    """Endpoint to receive CSP violation reports."""
    report = request.get_json()
    current_app.logger.warning(f"CSP Violation: {report}")
    return '', 204  # Acknowledge receipt

if __name__ == '__main__':
    # Flask's built-in development server is not designed for production use.
    # WSGI servers like Gunicorn and uWSGI are more robust and efficient for handling production traffic.
    # Use a WSGI server in production.

    # To obtain a valid SSL/TLS certificate, consider using Let's Encrypt (https://letsencrypt.org/),
    # a free, automated, and open Certificate Authority.  The `certbot` tool can automate the certificate
    # acquisition and renewal process.
    app.run(debug=False, host='127.0.0.1') # Remove debug=True and bind to localhost
    # app.run(debug=False, host='127.0.0.1', ssl_context=('path/to/cert.pem', 'path/to/key.pem')) # Example with real cert

