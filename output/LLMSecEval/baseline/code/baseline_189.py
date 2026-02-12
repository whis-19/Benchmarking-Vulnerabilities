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

    parsed_url = urlparse(url)
    if parsed_url.netloc == ALLOWED_DOMAIN or parsed_url.netloc.endswith("." + ALLOWED_DOMAIN):
        return True
    else:
        return False


@app.route('/redirect')
def redirect_invalid_url():
    """
    Redirects to the provided URL if it's valid and from the allowed domain.
    Otherwise, returns an error.

    Returns:
        Response: Redirects to the URL or returns an error message.
    """
    url = request.args.get('url')

    if not url:
        return "Error: URL parameter is missing.", 400  # Bad Request

    if is_valid_url(url):
        return redirect(url, code=302)  # Use 302 for temporary redirect
    else:
        return "Error: Invalid URL or domain not allowed.", 400  # Bad Request


@app.errorhandler(404)
def page_not_found(error):
    """Handles 404 errors."""
    return "Page not found", 404


if __name__ == '__main__':
    #  Never run this in production.  Use a proper WSGI server.
    app.run(debug=True, host='0.0.0.0', port=5000)

