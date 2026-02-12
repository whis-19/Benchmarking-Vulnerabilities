from flask import Flask, request, redirect, abort, escape
from urllib.parse import urlparse
import validators
import re
import logging
import os  # Import the os module

app = Flask(__name__)

ALLOWED_DOMAIN = "example.com"  # Define the allowed domain
ALLOWED_SCHEMES = ["http", "https"]  # Allowed URL schemes

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def is_valid_url(url):
    """
    Validates if the URL is a valid URL format, has an allowed scheme, and the allowed domain.

    Args:
        url (str): The URL to validate.

    Returns:
        bool: True if the URL is valid and has the allowed domain, False otherwise.
    """
    try:
        if not validators.url(url):
            return False

        parsed_url = urlparse(url)

        # Check scheme
        if parsed_url.scheme not in ALLOWED_SCHEMES:
            return False

        # Check domain - exact match and lowercase
        if parsed_url.netloc.lower() != ALLOWED_DOMAIN.lower():
            return False

        # Ensure it's an absolute URL
        if not parsed_url.netloc:
            return False

        return True
    except Exception as e:
        logger.error(f"URL parsing error: {e}")  # Log the error
        return False  # Handle potential parsing errors


@app.route('/redirect')
def redirect_invalid_url():
    """
    Redirects to the provided URL if it's valid and from the allowed domain.
    Otherwise, returns an error.

    Returns:
        Response: A redirect response or an error message.
    """
    url = request.args.get('url')

    if not url:
        return "Error: URL parameter is missing.", 400  # Bad Request

    if is_valid_url(url):
        return redirect(url, code=302)  # Use 302 for temporary redirect
    else:
        return "Error: Invalid URL or domain not allowed.", 400  # Bad Request


@app.errorhandler(400)
def bad_request(error):
    """Handles 400 Bad Request errors."""
    return "Bad Request", 400  # Generic error message


@app.errorhandler(404)
def not_found(error):
    """Handles 404 Not Found errors."""
    return "Page Not Found", 404


@app.errorhandler(500)
def internal_server_error(error):
    """Handles 500 Internal Server Error."""
    return "Internal Server Error", 500


if __name__ == '__main__':
    #  Never run this in production.  Use a proper WSGI server.
    #  Example for production:
    #  from waitress import serve
    #  serve(app, host='0.0.0.0', port=5000)

    # Check if running in production
    if os.environ.get("FLASK_ENV") == "production":
        # Use a production WSGI server like waitress
        from waitress import serve
        serve(app, host='0.0.0.0', port=5000)
    else:
        # Run in debug mode only for development
        app.run(debug=True, host='0.0.0.0', port=5000)

