import re
import secrets
import urllib.parse
from flask import Flask, request, redirect, abort, make_response
import logging

# Configure logging (replace with your preferred logging setup)
logging.basicConfig(level=logging.INFO)

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(32)  # Set a strong secret key

# Regular expression to match URLs containing example.com
# ^ and $ ensure the entire hostname matches, preventing subdomains or suffixes.
# \. escapes the dot, treating it literally.
ALLOWED_HOST = r"^(example\.com)$"

def is_valid_target(target):
    """
    Validates the target URL against the allowlist.

    Args:
        target: The URL to validate.

    Returns:
        True if the target is valid, False otherwise.
    """
    try:
        parsed_url = urllib.parse.urlparse(target)
        if not parsed_url.netloc:
            return False

        # Check the scheme
        if parsed_url.scheme not in ('http', 'https'):
            return False

        # Check if the hostname matches the allowed pattern
        if re.match(ALLOWED_HOST, parsed_url.netloc):
            return True
        else:
            return False
    except Exception as e:
        # Log the exception for debugging
        logging.error(f"Error parsing URL: {target}, Error: {e}")
        return False

@app.route('/')
def index():
    """
    Renders a simple index page.
    """
    return "<h1>Welcome!</h1>"

@app.route('/redirect')
def redirect_route():
    """
    Redirects to the target URL if it's valid, otherwise redirects to /.

    WARNING: This route is vulnerable to open redirect attacks, even with the
    `is_valid_target` function. An attacker could craft a URL like
    `https://example.com/evil.html` and trick users into visiting it.

    Consider implementing additional measures to mitigate this risk, such as:
    - Hashing/Signing: Generate a hash or signature of the target URL and
      include it in the redirect URL. The server can then verify the
      hash/signature before performing the redirect.
    - Limited Redirects: Instead of directly redirecting to the target URL,
      redirect to an intermediate page that displays a warning message and
      requires the user to confirm the redirect.
    """
    target = request.args.get('target')

    if not target:
        return redirect("/")

    if is_valid_target(target):
        return redirect(target)
    else:
        return redirect("/")

@app.after_request
def add_security_headers(response):
    """
    Adds security headers to the response.
    """
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    # Adjust CSP as needed.  For example, if using Google Analytics:
    # Content-Security-Policy: default-src 'self'; script-src 'self' https://www.google-analytics.com;
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self';"

    # If you use any inline scripts, you MUST use a nonce or hash in your CSP.
    # DO NOT use 'unsafe-inline'.  Example:
    # response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'nonce-YOUR_NONCE';"

    # strict-origin-when-cross-origin is a good default.  Other options include:
    # - no-referrer:  Sends no referrer information.
    # - origin: Sends only the origin (scheme, host, and port).
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    # In a production environment, always enforce HTTPS and use HSTS headers.
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload'

    # Remember to submit your site to the HSTS preload list *after* it has been
    # running with HSTS enabled for a sufficient period. Removal from the
    # preload list is difficult.
    return response

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)

