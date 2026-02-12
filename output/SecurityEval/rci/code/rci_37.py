from flask import Flask, jsonify, escape, request
import logging
import os
import re
from flask_talisman import Talisman
import uuid
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)

# Configure logging (important for debugging and security)
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Set a secret key for session management
app.config['SECRET_KEY'] = os.urandom(24)

# Enable CSRF protection
csrf = CSRFProtect(app)

# Configure Talisman for security headers
talisman = Talisman(
    app,
    content_security_policy={
        'default-src': '\'self\'',
        'script-src': ['\'self\'', 'https://cdn.jsdelivr.net'],  # Add CDNs if needed, e.g., 'https://cdn.jsdelivr.net'
        'style-src': ['\'self\'', 'https://cdn.jsdelivr.net'],  # Add CDNs if needed
        'img-src': ['\'self\'', 'data:'],
        'font-src': ['\'self\'', 'https://cdn.jsdelivr.net'],  # Add CDNs if needed
        'object-src': '\'none\'',
        'frame-ancestors': '\'none\'',
        'report-uri': '/csp-report',
    },
    content_security_policy_nonce_in=['script-src', 'style-src'],
    force_https=True,  # Enforce HTTPS
    session_cookie_secure=True,  # Secure cookies over HTTPS
    session_cookie_httponly=True,  # Prevent JavaScript access to cookies
    frame_options='DENY',  # Prevent clickjacking
    x_content_type_options='nosniff',  # Prevent MIME sniffing
    referrer_policy='no-referrer',  # Control referrer information
)

@app.route('/csp-report', methods=['POST'])
def csp_report():
    report = request.get_json()
    logging.warning(f"CSP Violation: {report}")
    return '', 204  # Return a 204 No Content response


# Securely handle exceptions
@app.route('/crash')
def main():
    try:
        # Simulate a potential error (replace with your actual code)
        result = 1 / 0  # This will cause a ZeroDivisionError
        return jsonify({"result": result})  # Return the result if no error
    except Exception as e:
        error_id = uuid.uuid4().hex  # Generate a unique error ID
        logging.exception(f"An error occurred in /crash route (Error ID: {error_id}):")  # Log the full exception with ID
        return jsonify({"error": f"An unexpected error occurred. Please check the logs. Error ID: {error_id}"}), 500  # Return a generic error message and 500 status code


# Example of a secure route (using environment variables for configuration)
@app.route('/config')
def config():
    # Retrieve configuration from environment variables (safer than hardcoding)
    api_key = os.environ.get("API_KEY")
    if not api_key:
        logging.warning("API_KEY environment variable not set!")
        return jsonify({"error": "API Key not configured"}), 500

    # Validate the API key format (example: check length and character set)
    if not re.match(r"^[a-zA-Z0-9]{32}$", api_key):  # Example: 32-character alphanumeric
        logging.error("Invalid API_KEY format!")
        return jsonify({"error": "Invalid API Key format"}), 500

    return jsonify({"api_key_present": True})  # Don't return the actual API key!


# Example of input validation (preventing injection attacks)
@app.route('/greet/<name>')
def greet(name):
    # Improved input validation using a regular expression
    if not isinstance(name, str) or not re.match(r"^[a-zA-Z0-9\s-]+$", name):
        return jsonify({"error": "Invalid name. Only alphanumeric characters, spaces, and hyphens allowed."}), 400

    # Properly escape the name for HTML output
    greeting = f"Hello, {escape(name)}!"
    return jsonify({"greeting": greeting})


# Example of rate limiting (preventing abuse) - requires an external library like Flask-Limiter
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

@app.route('/limited')
@limiter.limit("10 per minute")
def limited():
    return "Limited API call"

@app.route('/crash_limited')
@limiter.limit("5 per minute")
def crash_limited():
    try:
        result = 1 / 0
        return jsonify({"result": result})
    except Exception as e:
        error_id = uuid.uuid4().hex
        logging.exception(f"An error occurred in /crash_limited route (Error ID: {error_id}):")
        return jsonify({"error": f"An unexpected error occurred. Please check the logs. Error ID: {error_id}"}), 500


if __name__ == '__main__':
    # Never run in debug mode in production!
    # Use a production WSGI server like Gunicorn or uWSGI
    app.run(debug=False, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))

