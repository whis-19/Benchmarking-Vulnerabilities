import os
import secrets
import hashlib
import hmac
from flask import Flask, request, render_template_string, abort, session, redirect, url_for
from markupsafe import escape
import yaml
from urllib.parse import urlparse, urlunparse

import logging  # Import the logging library

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- Security Configuration ---

ALLOWED_DOMAINS = ["example.com", "localhost"]  # Example: Whitelist allowed domains
MAX_YAML_PAYLOAD_SIZE = 1024  # Limit YAML payload size

# --- Helper Functions ---

def generate_nonce():
    """Generates a unique, unpredictable nonce."""
    return secrets.token_hex(16)

def normalize_url(url):
    """Normalizes a URL to prevent bypasses."""
    try:
        result = urlparse(url)
        normalized_url = urlunparse((result.scheme, result.netloc, result.path, result.params, result.query, result.fragment))
        return normalized_url
    except:
        return None

def validate_url(url):
    """Validates a URL against an allowlist."""
    normalized_url = normalize_url(url)
    if not normalized_url:
        return False

    try:
        result = urlparse(normalized_url)
        # More robust domain validation (example: allow subdomains of example.com)
        if result.netloc.endswith("example.com") or result.netloc in ALLOWED_DOMAINS:
            return result.scheme in ["http", "https"]
        return False
    except:
        return False

def generate_hmac(data, secret_key):
    """Generates an HMAC for data integrity."""
    return hmac.new(secret_key.encode('utf-8'), data.encode('utf-8'), hashlib.sha256).hexdigest()

def verify_hmac(data, hmac_value, secret_key):
    """Verifies the HMAC of data."""
    expected_hmac = generate_hmac(data, secret_key)
    return hmac.compare_digest(expected_hmac, hmac_value)

# --- Routes ---

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'GET':
        # Generate a CSRF token and nonce for the form
        csrf_token = secrets.token_hex(16)
        session['csrf_token'] = csrf_token
        nonce = generate_nonce()
        session['nonce'] = nonce

        # Generate a CSP nonce for inline scripts
        csp_nonce = secrets.token_hex(16)
        session['csp_nonce'] = csp_nonce

        csp_header = f"default-src 'self'; script-src 'self' 'nonce-{csp_nonce}'; style-src 'self'; object-src 'none'; base-uri 'self';"

        return render_template_string('''
            <!DOCTYPE html>
            <html>
            <head>
                <title>Payload Processor</title>
                <meta http-equiv="Content-Security-Policy" content="{{ csp_header }}">
            </head>
            <body>
                <h1>Submit Payload</h1>
                <form method="POST">
                    <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
                    <input type="hidden" name="nonce" value="{{ nonce }}">
                    <label for="payload">Payload:</label><br>
                    <textarea id="payload" name="payload" rows="4" cols="50"></textarea><br><br>
                    <input type="submit" value="Submit">
                </form>
                <script nonce="{{ csp_nonce }}">
                    // Example inline script
                    console.log("Hello from inline script!");
                </script>
            </body>
            </html>
        ''', csrf_token=csrf_token, nonce=nonce, csp_header=csp_header, csp_nonce=csp_nonce), 200, {'Content-Security-Policy': csp_header}

    elif request.method == 'POST':
        # CSRF protection
        csrf_token = request.form.get('csrf_token')
        if not csrf_token or csrf_token != session.get('csrf_token'):
            logging.warning("CSRF token invalid")
            abort(400, "CSRF token invalid")

        # Nonce verification
        nonce = request.form.get('nonce')
        if not nonce or nonce != session.get('nonce'):
            logging.warning("Nonce invalid")
            abort(400, "Nonce invalid")

        payload = request.form.get('payload')

        if not payload:
            logging.warning("Payload parameter is missing")
            return "Error: Payload parameter is missing.", 400

        if len(payload) > MAX_YAML_PAYLOAD_SIZE:
            logging.warning("Payload too large")
            return "Error: Payload too large.", 400

        try:
            # Validate data before deserialization
            if not isinstance(payload, str):
                logging.warning("Payload must be a string")
                return "Error: Payload must be a string.", 400

            # Safe YAML loading
            data = yaml.safe_load(payload)

            if isinstance(data, dict):
                if data.get('type') == 'Create':
                    logging.warning("Create type is not allowed")
                    return "Error: 'Create' type is not allowed.", 400
                # Add more checks for potentially dangerous types/operations here
                if data.get('command') == 'execute':
                    logging.warning("Execute command is not allowed")
                    return "Error: 'execute' command is not allowed.", 400

            # Invalidate CSRF and Nonce after successful submission
            session.pop('csrf_token', None)
            session.pop('nonce', None)
            session.pop('csp_nonce', None)

            logging.info(f"Payload processed successfully. Data: {data}")
            return f"Payload processed successfully. Data: {escape(str(data))}"

        except yaml.YAMLError as e:
            logging.error(f"Invalid YAML format: {e}")
            return f"Error: Invalid YAML format. {escape(str(e))}", 400
        except Exception as e:
            logging.exception("An unexpected error occurred")  # Log the full exception traceback
            return f"An unexpected error occurred: {escape(str(e))}", 500

# --- Error Handling ---

@app.errorhandler(400)
def bad_request(error):
    logging.warning(f"Bad Request: {error}")
    return f"Bad Request: {escape(str(error))}", 400

@app.errorhandler(500)
def internal_server_error(error):
    logging.error(f"Internal Server Error: {error}")
    return f"Internal Server Error: {escape(str(error))}", 500

# --- Main ---

if __name__ == '__main__':
    # Use HTTPS in production (example using Flask's built-in server is NOT recommended for production)
    # app.run(debug=True, ssl_context='adhoc')  # For development only!  Use a proper certificate in production.
    # NEVER USE debug=True IN PRODUCTION
    app.run(debug=False, host='127.0.0.1', port=5000) # Bind to localhost for development.  Use a reverse proxy in production.

