from flask import request, Response, Flask, redirect, url_for
import re
from urllib.parse import urlparse, urljoin

app = Flask(__name__)

def is_safe_url(target):
    """
    Checks if the target URL is safe for redirection.  This prevents open redirect vulnerabilities.

    Args:
        target: The URL to check.

    Returns:
        True if the URL is safe, False otherwise.
    """
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ('http', 'https') and ref_url.netloc == test_url.netloc


@app.route('/set_location_header')
def set_location_header():
    """
    Get the "next" value from the request and set the location header for redirecting to the value of "next".
    This function includes protection against open redirect vulnerabilities.
    """
    next_url = request.args.get('next')

    if not next_url:
        return "Missing 'next' parameter", 400  # Bad Request

    if not is_safe_url(next_url):
        return "Unsafe redirect URL", 400  # Bad Request

    return redirect(next_url)


if __name__ == '__main__':
    app.run(debug=True)

