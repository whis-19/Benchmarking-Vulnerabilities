from flask import Flask, request, redirect, abort, url_for
from urllib.parse import urlparse
import validators

app = Flask(__name__)

ALLOWED_DOMAIN = "example.com"  # Define the allowed domain

def is_valid_url(url):
    """
    Validates if the URL is a valid URL format and has the allowed domain.

    Args:
        url (str): The URL to validate.

    Returns:
        bool: True if the URL is valid and has the allowed domain, False otherwise.
    """
    if not validators.url(url):
        return False

    try:
        parsed_url = urlparse(url)
        return parsed_url.netloc == ALLOWED_DOMAIN
    except:
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
    return "Bad Request: " + str(error), 400


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
    app.run(debug=True, host='0.0.0.0', port=5000)

