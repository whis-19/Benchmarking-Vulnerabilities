from flask import request, Response, Flask, redirect, url_for, session, logging
import re
import os
from urllib.parse import urlparse, urljoin, quote_plus
import logging

app = Flask(__name__)
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Mitigate XSS
app.config['SESSION_COOKIE_SECURE'] = True  # Only send cookies over HTTPS
app.config['SECRET_KEY'] = os.urandom(24)  # Required for Flask-WTF and sessions (CSRF)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# --- CSRF Protection (using a simplified example - Flask-WTF is strongly recommended) ---
# WARNING: This CSRF protection is for demonstration purposes only and is NOT production-ready.
# Use Flask-WTF for robust CSRF protection.
def generate_csrf_token():
    return os.urandom(24).hex()

@app.before_request
def csrf_protect():
    if request.method == "POST":
        token = request.form.get("csrf_token")
        if not token or token != session.get("csrf_token"):
            logger.warning("CSRF token is missing or invalid.")
            return "CSRF token is missing or invalid.", 400

@app.route('/get_csrf')
def get_csrf():
    session['csrf_token'] = generate_csrf_token()
    return session['csrf_token']

# --- End CSRF Protection ---


@app.after_request
def add_header(response):
    response.headers['Content-Type'] = 'text/html; charset=utf-8'
    # Consider adding a Content Security Policy (CSP) header here
    # Example: response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' cdn.example.com"
    # Customize the CSP header based on your application's needs.  For example, to allow scripts from a CDN, add 'script-src cdn.example.com'.
    return response


def is_safe_url(target):
    """
    Checks if the target URL is safe for redirection, preventing open redirects.
    """
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    # Check scheme and netloc.  Also, explicitly prevent javascript:void(0)
    return test_url.scheme in ('http', 'https') and ref_url.netloc == test_url.netloc and test_url.path != 'javascript:void(0)'


@app.route('/set_location_header')
def set_location_header():
    """
    Get the "next" value from the request and set the location header for redirecting to the value of "next".
    """
    next_url = request.args.get('next')

    if not next_url:
        logger.warning("Missing 'next' parameter in request.")
        return "Error: 'next' parameter is missing.", 400  # Bad Request

    if not is_safe_url(next_url):
        logger.warning(f"Unsafe URL attempted: {next_url}")
        return "Error: Unsafe URL for redirection.", 400

    # More restrictive regex:  Only allow paths within the application.
    # Example: /path1/path2?param1=value1&param2=value2
    # This regex is tailored to allow only relative paths with optional query parameters.
    # Adjust it based on your specific application's URL structure.
    # Consider using a more specific regex based on the allowed characters in your URLs.
    if not re.match(r"^/[-a-zA-Z0-9]+(/[-a-zA-Z0-9]+)*(\?[-a-zA-Z0-9]+=[-a-zA-Z0-9]+(&[-a-zA-Z0-9]+=[-a-zA-Z0-9]+)*)?$", next_url):
        logger.warning(f"Invalid characters in URL: {next_url}")
        return "Error: Invalid characters in URL.", 400

    # URL Encoding (using url_for for relative URLs)
    # Even with the regex, URL encoding is important to handle special characters correctly.
    # If 'next_url' was a full URL, you would need to URL-encode the *values* of the query parameters using urllib.parse.quote_plus.
    if next_url.startswith('/'):
        encoded_url = url_for(next_url[1:])  # remove leading slash for url_for
    else:
        # Example of handling external URLs (discouraged, but shown for completeness)
        parsed_url = urlparse(next_url)
        query_params = parsed_url.query
        if query_params:
            encoded_query_params = '&'.join([f"{quote_plus(k)}={quote_plus(v)}" for k, v in [param.split('=') for param in query_params.split('&')]])
            encoded_url = parsed_url.scheme + "://" + parsed_url.netloc + parsed_url.path + "?" + encoded_query_params
        else:
            encoded_url = next_url


    return redirect(encoded_url)


@app.route('/example')
def example_page():
    """
    An example page that uses the redirect.  This demonstrates how to include the CSRF token.
    """
    csrf_token = session.get('csrf_token')
    return f"""
    <h1>Example Page</h1>
    <p>Click the button below to be redirected.</p>
    <form action="/set_location_header?next=/example2" method="post">
        <input type="hidden" name="csrf_token" value="{csrf_token}">
        <button type="submit">Redirect to /example2</button>
    </form>
    """

@app.route('/example2')
def example_page_2():
    return "<h1>Example Page 2</h1>"


if __name__ == '__main__':
    app.secret_key = os.urandom(24) # Needed for session
    app.run(debug=True)

