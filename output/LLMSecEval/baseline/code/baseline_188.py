from flask import Flask, redirect, abort, request
from urllib.parse import urlparse

app = Flask(__name__)

ALLOWED_DOMAINS = ["example.com"]  # Define allowed domains

def is_safe_url(target):
    """
    Checks if the target URL is safe to redirect to.

    This function prevents open redirect vulnerabilities by ensuring that the
    target URL is within an allowed domain.  It uses urlparse to extract the
    netloc (network location) and compares it against a list of allowed domains.

    Args:
        target: The URL to redirect to.

    Returns:
        True if the URL is safe, False otherwise.
    """
    try:
        parsed_url = urlparse(target)
        # Check if the scheme is allowed (e.g., http, https)
        if parsed_url.scheme not in ('http', 'https'):
            return False

        # Check if the netloc (domain) is in the allowed list
        if parsed_url.netloc in ALLOWED_DOMAINS:
            return True
        else:
            return False
    except Exception:
        # Handle parsing errors gracefully.  Return False to be safe.
        return False


@app.route('/redirect/<path:url>')
def redirect_invalid_url(url):
    """
    Redirects to the given URL if it's from an allowed domain.

    Args:
        url: The URL to redirect to.

    Returns:
        A redirect response if the URL is safe, an error message otherwise.
    """
    if is_safe_url(url):
        return redirect(url)
    else:
        abort(400, description="Invalid URL.  Redirect to this domain is not allowed.")


@app.errorhandler(400)
def bad_request(e):
    """
    Handles 400 Bad Request errors.
    """
    return f"Bad Request: {e.description}", 400


if __name__ == '__main__':
    #  Never run this in production.  Use a proper WSGI server.
    #  Also, never expose this directly to the internet without a reverse proxy
    #  handling SSL/TLS.
    app.run(debug=True, host='0.0.0.0', port=5000)

