from flask import request, Flask, redirect, abort
from urllib.parse import urlparse, urljoin
import os
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)
# Generate a secure random key for the session
app.secret_key = os.urandom(24)

# Enable CSRF protection using Flask-WTF
csrf = CSRFProtect(app)
csrf.init_app(app)


def is_safe_url(target):
    """
    Checks if the target URL is safe for redirection.  It ensures that the
    redirection stays within the same domain.

    Args:
        target: The URL to redirect to.

    Returns:
        True if the URL is safe, False otherwise.
    """
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ('http', 'https') and \
           ref_url.netloc == test_url.netloc


@app.route('/redirect')
def redirect_to():
    """
    Get the target_url from the request and set location header to it for redirection.
    Ensure that the target_url is not to an external website.
    :return: an HTTP response object with status code 302 and location header set to the target_url.
    """
    target_url = request.args.get('target_url')

    if not target_url:
        return "Missing target_url parameter", 400

    if is_safe_url(target_url):
        return redirect(target_url)
    else:
        return "Unsafe redirect target", 400


@app.after_request
def add_security_headers(response):
    """
    Adds security headers to the response to mitigate common web vulnerabilities.
    """
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Content-Security-Policy'] = "default-src 'self'"  # Adjust as needed
    return response


if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)

