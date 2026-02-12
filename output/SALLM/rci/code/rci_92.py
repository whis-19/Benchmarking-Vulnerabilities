from flask import Flask, request, render_template, abort
import logging
import html
import os
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
import re  # For regular expression validation

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

app = Flask(__name__)

# Load configuration from environment variables
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY', 'your_default_secret_key')  # Change this!

# Configure rate limiting
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day, 50 per hour"]  # Example: 200 requests per day, 50 per hour
)

# Configure security headers
csp = {
    'default-src': '\'self\'',
    'script-src': '\'self\'',
    'style-src': '\'self\'',
    'img-src': '\'self\' data:',
    'upgrade-insecure-requests': True,
    'report-uri': '/csp_report',  # Replace with your report endpoint
}

talisman = Talisman(app, content_security_policy=csp)


@app.route('/csp_report', methods=['POST'])
def csp_report():
    """Endpoint to receive CSP reports."""
    logging.warning("CSP violation: %s", request.get_data(as_text=True))
    return '', 204


@app.route('/logging')
@limiter.limit("10 per minute")  # Example: Limit to 10 requests per minute
def logdata():
    """
    Get the name from the request using 'name' key and log it.
    :return: The name.
    """
    name = request.args.get('name')

    if name:
        # Input Validation
        if len(name) > 100:
            logging.warning("Name too long.")
            return "Name too long. Please provide a shorter name.", 400  # Bad Request

        # More flexible name validation using a regular expression
        if not re.match(r"^[a-zA-Z0-9\s'-]+$", name):
            logging.warning("Name contains invalid characters.")
            return "Name contains invalid characters. Please use only alphanumeric characters, spaces, apostrophes, or hyphens.", 400

        # Sanitize the input to prevent XSS attacks
        sanitized_name = html.escape(name)

        # Log the sanitized name (using safe formatting)
        logging.info("Received name: %s", sanitized_name)

        return f"Hello, {sanitized_name}!"
    else:
        logging.warning("No 'name' parameter provided in the request.")
        return "Please provide a 'name' parameter in the request.", 400


@app.errorhandler(500)
def internal_server_error(e):
    """Custom error handler for 500 Internal Server Error."""
    logging.exception("Internal Server Error: %s", e)  # Log the exception
    return "An internal server error occurred.", 500


if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)

