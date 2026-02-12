import secrets
import logging
import yaml
import json
from flask import Flask, request, render_template, redirect, escape, abort, session
from urllib.parse import urlparse
from cerberus import Validator

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

# Session Configuration
app.config['SESSION_COOKIE_SECURE'] = True  # Only send cookies over HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True # Prevent JavaScript access
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax' # Recommended for CSRF protection
# Consider 'Strict' if appropriate
# app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Allowed domains/IPs (for redirects, etc.)
ALLOWED_DOMAINS = ["example.com", "127.0.0.1"]
ALLOWED_URL_SCHEMES = ["http", "https"]

# YAML Schema Validation
yaml_schema = {
    'name': {'type': 'string', 'required': True, 'maxlength': 100},
    'age': {'type': 'integer', 'min': 0, 'max': 150},
    'email': {'type': 'string', 'regex': '^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', 'maxlength': 255},
    'type': {'type': 'string', 'allowed': ['profile', 'settings']} # Example of allowed values
}
yaml_validator = Validator(yaml_schema)

# CSRF Protection
def generate_csrf_token():
    token = secrets.token_hex(16)
    session['csrf_token'] = token
    return token

def validate_csrf_token(token):
    return session.get('csrf_token') == token

# URL Validation and Sanitization
def validate_and_sanitize_url(url):
    try:
        parsed_url = urlparse(url)

        if not parsed_url.scheme in ALLOWED_URL_SCHEMES:
            logging.warning(f"Disallowed URL scheme: {parsed_url.scheme}")
            return None

        hostname = parsed_url.hostname
        if not hostname:
            logging.warning(f"No hostname found in URL: {url}")
            return None

        # Canonicalize the hostname (lowercase)
        hostname = hostname.lower()

        # Check if the hostname is allowed
        if hostname not in ALLOWED_DOMAINS:
            logging.warning(f"Disallowed domain: {hostname}")
            return None

        # Reconstruct the URL to prevent encoding issues and relative redirects to other domains
        sanitized_url = parsed_url.scheme + "://" + hostname + parsed_url.path
        return sanitized_url

    except Exception as e:
        logging.exception(f"Error validating URL: {url}")
        return None

# CSP Header
@app.after_request
def add_csp_header(response):
    #  REPLACE WITH NONCES OR HASHES FOR INLINE STYLES AND SCRIPTS
    csp = "; ".join([
        "default-src 'self'",
        "script-src 'self'",  # Remove 'unsafe-inline' - USE NONCES/HASHES
        "style-src 'self'",  # Remove 'unsafe-inline' - USE NONCES/HASHES
        "img-src 'self' data:",
        "font-src 'self'",
        "object-src 'none'",
        "frame-ancestors 'none'",
        "base-uri 'self'",
        "form-action 'self'",
        # "report-uri /csp_report" # Add this and implement the route
    ])
    response.headers['Content-Security-Policy'] = csp
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block' # Consider removing
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload'
    response.headers['Cache-Control'] = 'no-store'
    response.headers['Pragma'] = 'no-cache'
    return response

# @app.route("/csp_report", methods=['POST'])
# def csp_report():
#     # Implement logic to handle CSP reports
#     report = request.get_json()
#     logging.warning(f"CSP Violation: {report}")
#     return '', 204

@app.route("/", methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        # CSRF Protection
        csrf_token = request.form.get('csrf_token')
        if not csrf_token or not validate_csrf_token(csrf_token):
            logging.warning("CSRF token validation failed.")
            abort(400)

        payload = request.form.get('payload')

        if not payload:
            error_message = "Payload parameter is missing."
            logging.warning(error_message)
            return render_template('index.html', error=error_message, csrf_token=generate_csrf_token())

        try:
            # Validate data before deserialization
            if not isinstance(payload, str):
                raise ValueError("Payload must be a string.")

            # Safe YAML loading
            data = yaml.safe_load(payload)

            # YAML Schema Validation
            if not yaml_validator.validate(data):
                error_message = f"Invalid YAML data: {yaml_validator.errors}"
                logging.warning(error_message)
                return render_template('index.html', error=error_message, csrf_token=generate_csrf_token())

            if not isinstance(data, dict):
                raise ValueError("Payload must be a YAML dictionary.")

            # Check for disallowed 'type' value
            if 'type' in data and data['type'] == 'Create':
                error_message = "Create action is not allowed."
                logging.warning(error_message)
                return render_template('index.html', error=error_message, csrf_token=generate_csrf_token())

            # Process the data safely (example: display it)
            processed_data = json.dumps(data)
            processed_data = escape(processed_data) # Ensure context-aware escaping
            success_message = f"Data processed successfully: {processed_data}"
            logging.info(success_message)
            return render_template('index.html', success=success_message, csrf_token=generate_csrf_token())

        except yaml.YAMLError as e:
            error_message = f"Invalid YAML format: {str(e)}"
            logging.warning(error_message)
            return render_template('index.html', error=error_message, csrf_token=generate_csrf_token())
        except ValueError as e:
            error_message = str(e)
            logging.warning(error_message)
            return render_template('index.html', error=error_message, csrf_token=generate_csrf_token())
        except Exception as e:
            error_message = f"An unexpected error occurred: {str(e)}"
            logging.exception(error_message)
            return render_template('index.html', error=error_message, csrf_token=generate_csrf_token())

    # GET request
    return render_template('index.html', csrf_token=generate_csrf_token())

@app.route("/redirect")
def redirect_url():
    target = request.args.get('target')

    if not target:
        return "No target URL provided", 400

    sanitized_url = validate_and_sanitize_url(target)

    if sanitized_url:
        # Use relative redirects if possible
        if sanitized_url.startswith("/"):
            return redirect(sanitized_url)
        else:
            return redirect(sanitized_url)
    else:
        return "Invalid or disallowed URL", 400

@app.errorhandler(400)
def bad_request(e):
    logging.error(f"Bad Request: {e}")
    return render_template('error.html', error="Bad Request"), 400

@app.errorhandler(500)
def internal_server_error(e):
    logging.exception(f"Internal Server Error: {e}")
    return render_template('error.html', error="Internal Server Error"), 500

if __name__ == "__main__":
    # Use HTTPS in production
    app.run(debug=True) #Remove debug=True in production - NEVER RUN IN DEBUG MODE IN PRODUCTION

