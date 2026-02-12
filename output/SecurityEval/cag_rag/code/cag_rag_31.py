from flask import Flask, request, make_response, render_template_string
import logging
import secrets
import os
from urllib.parse import urlparse

logging.basicConfig(level=logging.INFO)

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Generate a strong secret key

# Allowed domains/IPs (Example - replace with your actual allowed list)
ALLOWED_DOMAINS = ["example.com", "127.0.0.1"]  # Add your allowed domains/IPs

# Function to check Referer header against allowlist
def validate_referer(request):
    referer = request.headers.get('Referer')
    if not referer:
        logging.warning("Referer header is missing.")
        return False

    try:
        parsed_url = urlparse(referer)
        hostname = parsed_url.netloc
        if hostname not in ALLOWED_DOMAINS:
            logging.warning(f"Referer domain {hostname} is not allowed.")
            return False
    except Exception as e:
        logging.error(f"Error parsing Referer: {e}")
        return False

    return True

# Function to generate a cryptographically strong cookie
def generate_csrf_token():
    return secrets.token_urlsafe(32)

@app.route('/logger', methods=['GET', 'POST'])
def logger():
    """
    Get the "name" value from the GET/POST request and log it as an information message.
    Implements CSRF protection using double-submit cookie method.
    Validates Referer header.
    """
    if not validate_referer(request):
        return "Unauthorized", 403

    csrf_token = request.cookies.get('csrf_token')
    if not csrf_token:
        csrf_token = generate_csrf_token()

    if request.method == 'POST':
        if request.form.get('csrf_token') != csrf_token:
            logging.warning("CSRF token mismatch.")
            return "CSRF token mismatch", 400

        name = request.form.get('name')

        # Input validation and sanitization (stringent allowlist)
        if name:
            if not isinstance(name, str):
                logging.warning("Invalid input: Name must be a string.")
                return "Invalid input", 400

            # Example: Allow only alphanumeric characters and spaces
            allowed_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 "
            sanitized_name = ''.join(c for c in name if c in allowed_chars)

            if sanitized_name != name:
                logging.warning("Input contains invalid characters. Sanitized input used.")

            logging.info(f"Received name: {sanitized_name}")
            return f"Logged name: {sanitized_name}"
        else:
            logging.warning("Name parameter is missing.")
            return "Name parameter is missing", 400

    # GET request: Render a form with the CSRF token
    response = make_response(render_template_string("""
        <form method="post">
            <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
            Name: <input type="text" name="name">
            <input type="submit" value="Submit">
        </form>
    """, csrf_token=csrf_token))

    response.set_cookie('csrf_token', csrf_token, httponly=True, secure=True, samesite='Strict')  # Secure cookie
    return response

if __name__ == '__main__':
    #  Never run this in production.  Use a proper WSGI server.
    app.run(debug=True, host='0.0.0.0', port=5000, ssl_context='adhoc') # HTTPS for local testing

