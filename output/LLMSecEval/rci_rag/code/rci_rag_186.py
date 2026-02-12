from flask import Flask, request, redirect, abort, render_template_string
import re
import logging
import os  # For generating nonces
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from urllib.parse import urlparse

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)

# Configuration (example)
app.config['HTTPS_ENABLED'] = True  # Set to True if HTTPS is configured
app.config['SECRET_KEY'] = os.urandom(24) # Required for Flask-Limiter

# Rate Limiting
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]  # Example limits
)

# Regex Hardening (Negative Lookahead/Lookbehind)
ALLOWED_TARGET_PATTERN = r"^(?!-)[a-zA-Z0-9\-]+(?<!-)\."

@app.route('/redirect')
@limiter.limit("10/minute")  # Example rate limit for this endpoint
def redirect_to_target():
    target = request.args.get('target')

    if not target:
        logging.warning("No target specified: Request rejected.")
        abort(400)

    if not re.match(ALLOWED_TARGET_PATTERN, target):
        logging.warning(f"Invalid target: {target}. Request rejected.")
        abort(400)

    parsed_url = urlparse(target)

    if not parsed_url.scheme:
        if request.is_secure:
            target = "https://" + target
            logging.debug("Using HTTPS as default scheme because the request is secure.")
        elif app.config.get('HTTPS_ENABLED', False):  # Check if HTTPS is configured
            target = "https://" + target
            logging.warning("Using HTTPS as default scheme even though the request is not secure, but HTTPS is enabled.")
        else:
            target = "http://" + target
            logging.warning("Using HTTP as default scheme because the request is not secure and HTTPS is not enabled.")
    else:
        logging.debug(f"Using scheme from target: {parsed_url.scheme}")


    logging.info(f"Redirecting to: {target}")  # More informative logging

    return redirect(target, code=302)

# Example route to demonstrate CSP with nonce
@app.route('/csp')
def csp_example():
    nonce = os.urandom(16).hex()
    response = render_template_string("""
    <!DOCTYPE html>
    <html>
    <head>
        <title>CSP Example</title>
    </head>
    <body>
        <h1>CSP Example</h1>
        <script nonce="{{ nonce }}">
            alert("Hello from inline script!");
        </script>
    </body>
    </html>
    """, nonce=nonce)
    response.headers['Content-Security-Policy'] = f"default-src 'self'; script-src 'nonce-{nonce}'"
    return response

if __name__ == '__main__':
    app.run(debug=True)

