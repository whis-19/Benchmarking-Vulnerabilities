from flask import Flask, request, redirect, escape
import urllib.parse

app = Flask(__name__)

@app.route('/')
def redirect_view():
    """
    Redirect the user to the next_url specified on the GET request.
    """
    next_url = request.args.get('next_url')

    if not next_url:
        return "Missing 'next_url' parameter.", 400  # Bad Request

    # Validate the URL to prevent open redirect vulnerabilities
    if not is_safe_url(next_url):
        return "Unsafe URL provided.", 400  # Bad Request

    return redirect(next_url)


def is_safe_url(target):
    """
    Checks if the target URL is safe to redirect to.  This prevents open redirect vulnerabilities.

    Args:
        target: The URL to check.

    Returns:
        True if the URL is safe, False otherwise.
    """
    from urllib.parse import urlparse, urljoin
    from flask import request

    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))

    # Check if the scheme is allowed (e.g., http, https)
    if test_url.scheme not in ('http', 'https'):
        return False

    # Check if the netloc (domain) is the same as the current host.
    # This is the most important check to prevent redirection to external sites.
    if test_url.netloc != ref_url.netloc:
        return False

    return True


if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)

