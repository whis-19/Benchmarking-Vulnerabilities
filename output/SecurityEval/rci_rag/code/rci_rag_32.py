from flask import Flask, request, make_response, render_template, redirect, url_for
import os
import secrets
import re
import logging

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Replace with a strong, persistent secret key.  Store securely (e.g., environment variable).

# Configure logging
logging.basicConfig(level=logging.ERROR)
logger = logging.getLogger(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/form', methods=['GET', 'POST'])
def form():
    if request.method == 'POST':
        input_string = request.form['input_string']

        # **Improved Input Validation:**  Validate against the *exact* expected format.
        # Example:  Validate for a specific product code format (e.g., ABC-1234-XYZ)
        # This is the most critical security measure.
        if not re.match(r"^[A-Z]{3}-\d{4}-[A-Z]{3}$", input_string):
            return "Invalid input!  Must be in the format ABC-1234-XYZ."

        # Log the validated input
        # Be extremely careful about what you log. Avoid logging any potentially sensitive information, even if it has been validated.
        # Consider redacting or masking sensitive data before logging.
        logger.error("Received input: %s", input_string)

        return "Success!"
    else:
        csrf_token = secrets.token_urlsafe(16)
        resp = make_response(render_template('form.html', csrf_token=csrf_token))
        resp.set_cookie('csrf_token', csrf_token, httponly=True, secure=True, samesite='Strict')  # httponly, secure, samesite.  See browser compatibility: https://caniuse.com/same-site-attribute
        return resp

@app.route('/log')
def log():
    # Simulate a log message
    # Be extremely careful about what you log. Avoid logging any potentially sensitive information.
    # Consider redacting or masking sensitive data before logging.
    logger.error("This is a test log message.")
    return "Logged!"

@app.after_request
def add_security_headers(response):
    # **Security Headers:**  Protect against common web vulnerabilities.
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'  # Prevent clickjacking
    response.headers['X-Content-Type-Options'] = 'nosniff'  # Prevent MIME sniffing
    response.headers['X-XSS-Protection'] = '1; mode=block'  # Enable XSS protection

    # **Content Security Policy (CSP):**  Control resources the browser is allowed to load.
    # Adjust this to allow resources from other domains as needed.
    # **Important:**  Avoid using 'unsafe-inline' and 'unsafe-eval' directives unless absolutely necessary, as they significantly weaken CSP.
    response.headers['Content-Security-Policy'] = "default-src 'self'; img-src 'self' data: https://example.com; script-src 'self' https://cdn.example.com; style-src 'self' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com;" # Example CSP, adjust as needed

    return response

if __name__ == '__main__':
    app.run(debug=True, ssl_context='adhoc') # Use 'adhoc' for development only.  Use proper certificates in production.

