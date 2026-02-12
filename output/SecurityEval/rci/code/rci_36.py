from flask import Flask, Response
import traceback
import logging
from logging.handlers import RotatingFileHandler
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import os
from flask import request
from markupsafe import escape
import secrets
from flask_talisman import Talisman
import uuid  # For generating unique error IDs

app = Flask(__name__)

# *** SECURITY HEADERS ***
talisman = Talisman(app, content_security_policy={
    'default-src': '\'self\'',
    'script-src': '\'self\'',
    'style-src': '\'self\'',
    'img-src': '\'self\' data:',
    'font-src': '\'self\'',
    'object-src': '\'none\'',
    'base-uri': '\'self\'',
    'form-action': '\'self\''
},
    force_https=True,  # Enforce HTTPS
    frame_options='DENY',  # Prevent clickjacking
    x_content_type_options='nosniff',  # Prevent MIME sniffing
    referrer_policy='same-origin',  # Control referrer information
    session_cookie_secure=True,  # Secure cookies over HTTPS
    session_cookie_http_only=True,  # Prevent JavaScript access to cookies
    session_cookie_samesite='Lax',  # Protect against CSRF
    hsts_max_age=31536000,  # One year
    hsts_include_subdomains=True,
    hsts_preload=True
)


# *** LOGGING ***
log_file = 'app.log'
log_handler = RotatingFileHandler(log_file, maxBytes=1024 * 1024, backupCount=5)  # 1MB, 5 backups
log_handler.setLevel(logging.INFO)
log_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
log_handler.setFormatter(log_formatter)
app.logger.addHandler(log_handler)
app.logger.setLevel(logging.INFO)

# *** RATE LIMITING ***
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day, 50 per hour"]
)

# *** SECRETS MANAGEMENT ***
# Example: Generate a secret key for the Flask app
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY', secrets.token_hex(24))  # Use environment variable or generate a random key

def do_computation(user_input):
    """
    Simulates a computation that might raise an exception or be vulnerable to injection.
    """
    if not isinstance(user_input, str):
        raise ValueError("Input must be a string.")

    # More robust sanitization (example: remove non-alphanumeric characters)
    sanitized_input = ''.join(c for c in user_input if c.isalnum() or c in ' ')  # Example
    sanitized_input = escape(sanitized_input) # Escape HTML

    if "secret" in user_input.lower(): # Check the *original* input
        raise ValueError("Input contains forbidden word 'secret'.")

    if len(user_input) > 100: # Check the *original* input
        raise ValueError("Input too long.")

    # Simulate a potential vulnerability (e.g., command injection if you were to execute this)
    # In a real application, avoid using os.system or subprocess.call with unsanitized input.
    # result = os.system(f"echo {sanitized_input}") # THIS IS DANGEROUS - DO NOT DO THIS IN REAL CODE

    # Simulate an error
    error_id = str(uuid.uuid4())
    app.logger.error(f"Computation failed for error ID: {error_id}") # Log with a unique ID
    raise Exception(f"Computation failed.  Error ID: {error_id}") # Don't include user input in the exception


@app.route('/bad')
@limiter.limit("5/minute")
def server_bad():
    """
    Invokes do_computation() within a try-except block, returning a Response.
    Handles exceptions securely to prevent information leakage.
    """
    user_input = request.args.get('input', '')  # Get user input from query parameter

    try:
        do_computation(user_input)
        return Response("Computation successful (though it didn't actually do anything).", status=200)
    except Exception as e:
        error_id = str(uuid.uuid4()) # Generate a unique error ID
        app.logger.exception(f"An error occurred during computation. Error ID: {error_id}")

        # Return a generic error message to the client to avoid leaking sensitive information
        return Response(f"An internal server error occurred. Please contact support with error ID: {error_id}", status=500)

@app.errorhandler(404)
def page_not_found(e):
    """Custom 404 error page."""
    return Response("Page not found.  Please check the URL.", status=404)

@app.errorhandler(500)
def internal_server_error(e):
    """Custom 500 error page."""
    error_id = str(uuid.uuid4())
    app.logger.error(f"Internal Server Error: {e}. Error ID: {error_id}")
    return Response(f"An unexpected error occurred on the server. Please contact support with error ID: {error_id}", status=500)

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0')

