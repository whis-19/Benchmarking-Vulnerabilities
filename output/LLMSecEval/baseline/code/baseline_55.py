from flask import Flask, redirect, abort, request
from urllib.parse import urlparse

app = Flask(__name__)

ALLOWED_DOMAINS = ["example.com"]  # Define allowed domains

def is_safe_url(url):
    """
    Checks if a URL is safe to redirect to.  This function is crucial
    for preventing open redirect vulnerabilities.

    Args:
        url (str): The URL to check.

    Returns:
        bool: True if the URL is safe, False otherwise.
    """
    try:
        result = urlparse(url)

        # Check if the scheme is allowed (https is generally preferred)
        if result.scheme not in ("http", "https"):
            return False

        # Check if the netloc (domain) is in the allowed list
        if result.netloc not in ALLOWED_DOMAINS:
            return False

        return True

    except Exception:
        # Handle parsing errors (e.g., malformed URLs)
        return False


@app.route('/redirect/<path:url>')
def redirect_invalid_url(url):
    """
    Redirects to a URL if it's from an allowed domain.  Otherwise, returns an error.

    Args:
        url (str): The URL to redirect to.

    Returns:
        flask.Response: A redirect response or an error message.
    """

    if is_safe_url(url):
        return redirect(url)
    else:
        # Log the attempted redirect for security auditing
        app.logger.warning(f"Attempted redirect to unsafe URL: {url} from IP: {request.remote_addr}")
        abort(400, description="Invalid URL.  Redirect blocked for security reasons.")


@app.errorhandler(400)
def bad_request(e):
    """
    Handles 400 Bad Request errors.  Provides a more user-friendly error message.
    """
    return f"Bad Request: {e.description}", 400


if __name__ == '__main__':
    #  Never run this in production with debug=True.  It's a security risk.
    #  Use a production WSGI server like gunicorn or uWSGI.
    app.run(debug=True, host='0.0.0.0', port=5000)

