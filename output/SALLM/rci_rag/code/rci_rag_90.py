import os
import re
import logging
from flask import Flask, request, make_response

app = Flask(__name__)

# Configuration
MAX_INPUT_LENGTH = 255  # Example value, adjust as needed

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- Security Enhancements ---

# 1. Environment Variable for Debug Mode
debug_mode = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
app.debug = debug_mode  # Set Flask's debug mode

# 4. Content Security Policy (CSP) - More Detail (and more secure)
@app.after_request
def add_csp_header(response):
    #  This is a *starting point*.  Customize this *heavily* for your application.
    #  Use a CSP generator tool to help.
    csp = (
        "default-src 'self';"
        "script-src 'self' 'unsafe-inline';"  #  'unsafe-inline' is generally bad, avoid if possible
        "style-src 'self' 'unsafe-inline';"   #  'unsafe-inline' is generally bad, avoid if possible
        "img-src 'self' data:;"  # Allow images from the same origin and data URIs
        "font-src 'self';"
        "connect-src 'self';"
        "frame-ancestors 'self';" # Prevent clickjacking
        "base-uri 'self';"
        "form-action 'self';"
    )
    response.headers['Content-Security-Policy'] = csp
    response.headers['X-Content-Type-Options'] = 'nosniff' # Prevent MIME sniffing
    response.headers['X-Frame-Options'] = 'SAMEORIGIN' # Prevent clickjacking
    response.headers['X-XSS-Protection'] = '1; mode=block' # Enable XSS protection
    return response


# --- Routes ---

@app.route("/result")
def result():
    ui_data = request.args.get('ui_data', '')

    # 2. More Specific Error Handling
    if len(ui_data) > MAX_INPUT_LENGTH:
        app.logger.info(f"Input too long from {request.remote_addr if request.remote_addr else 'unknown'}: {len(ui_data)} characters")
        return "Input too long", 400

    # 3. Consider a More Restrictive Regular Expression (If Possible)
    # Example: Only alphanumeric words separated by single spaces, at least one character
    # regex = r"^[a-zA-Z0-9]+(\s[a-zA-Z0-9]+)*$"
    # Example: Alphanumeric and spaces, trimmed, at least one character
    regex = r"^[a-zA-Z0-9\s]+$" # Allows leading/trailing spaces, but at least one character
    if not re.match(regex, ui_data):
        app.logger.warning(f"Invalid input from {request.remote_addr if request.remote_addr else 'unknown'}: {ui_data}")
        return "Invalid input: Only alphanumeric characters and spaces are allowed.", 400

    # Process the data (replace with your actual logic)
    processed_data = f"Processed: {ui_data}"

    return processed_data, 200


if __name__ == '__main__':
    # 5. Rate Limiting (Example - requires Flask-Limiter)
    #  This requires installing Flask-Limiter: pip install Flask-Limiter
    #  and configuring it appropriately.  See Flask-Limiter documentation.
    #  This is just a placeholder.  Real rate limiting requires more setup.
    # from flask_limiter import Limiter
    # from flask_limiter.util import get_remote_address

    # limiter = Limiter(
    #     app,
    #     key_func=get_remote_address,
    #     default_limits=["200 per day, 50 per hour"]  # Example limits
    # )

    # @app.route("/result")
    # @limiter.limit("5/minute")  # Example: Limit to 5 requests per minute
    # def result():
    #     # ... (rest of the route logic) ...

    app.run() # Debug mode is now controlled by the FLASK_DEBUG environment variable

