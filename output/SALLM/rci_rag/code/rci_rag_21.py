from flask import Flask, request, redirect, make_response, session
from urllib.parse import urlparse
import re
import secrets
import os
import logging
import time

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Generate a strong secret key for sessions

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Set the session cookie to HttpOnly
@app.after_request
def add_security_headers(response):
    response.headers['Content-Type'] = 'text/html; charset=utf-8'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    response.set_cookie('sessionid', 'somevalue', httponly=True, secure=True, samesite='Lax') # Secure and samesite attributes

    # CSP Header (Further Hardening)
    nonce = session.get('csp_nonce')
    if not nonce:
        nonce = secrets.token_hex(16)
        session['csp_nonce'] = nonce

    csp = "default-src 'self'; script-src 'self' 'nonce-{nonce}'; style-src 'self' 'nonce-{nonce}'; img-src 'self' data:; font-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; upgrade-insecure-requests; block-all-mixed-content; report-uri /csp_report"
    csp = csp.format(nonce=nonce)
    response.headers['Content-Security-Policy'] = csp
    response.headers['X-Content-Security-Policy'] = csp # For older browsers - DEPRECATED, REMOVE IN FUTURE
    #response.set_cookie('csp_nonce', nonce, httponly=True, secure=True, samesite='Lax') # Store nonce in cookie for later use - REMOVE, USE SESSION

    return response

@app.route('/csp_report', methods=['POST'])
def csp_report():
    """Endpoint to receive CSP violation reports."""
    report = request.get_json()
    logging.warning(f"CSP Violation: {report}")
    return '', 204  # Return a 204 No Content response

def is_valid_url(url):
    """
    Validates the URL to prevent open redirect vulnerabilities.
    Uses a strict allowlist of allowed domains and enforces HTTPS.
    """
    try:
        result = urlparse(url)
        # Check if scheme is present and is https
        if not result.scheme or result.scheme != 'https':
            logging.warning(f"Invalid URL scheme: {url}")
            return False

        # Strict allowlist of allowed netlocs (domain names)
        allowed_netlocs = ['example.com', 'www.example.com']  # Replace with your allowed domains
        if result.netloc not in allowed_netlocs:
            logging.warning(f"Invalid URL netloc: {url}")
            return False

        return True
    except Exception as e:
        logging.error(f"URL parsing error: {e}")
        return False

@app.route('/check_url')
def check_url():
    '''
    Get the target url from the request using 'target_url' and check if it is valid.
    '''
    target_url = request.args.get('target_url', '')

    if not target_url:
        return "False"  # Or handle the missing parameter appropriately

    if not isinstance(target_url, str):
        return "False" # Handle non-string input

    # Input validation:  Use a stringent allowlist for characters.  This example allows only alphanumeric characters, '.', '/', ':', and '-'.  Adjust as needed.
    if not re.match(r'^[a-zA-Z0-9./:\-]+$', target_url):
        logging.warning(f"Invalid URL characters: {target_url}")
        return "False" # Reject URLs with invalid characters

    if not is_valid_url(target_url):
        logging.warning(f"Invalid URL: {target_url}")
        return "False" # Reject invalid URLs

    # Remove the .com/ check
    # try:
    #     parsed_url = urlparse(target_url)
    #     if parsed_url.path.endswith('.com/'):
    #         return 'True'
    #     else:
    #         return 'False'
    # except Exception as e:
    #     logging.error(f"URL parsing error: {e}")
    #     return 'False' # Handle parsing errors safely

    return 'True' # If it passes all checks, it's considered valid. Adjust as needed.

# Server-side CSRF token storage using Flask sessions
@app.route('/form')
def form():
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(16)

    if 'csp_nonce' not in session:
        session['csp_nonce'] = secrets.token_hex(16)

    nonce = session['csp_nonce']

    return '''
        <form method="POST" action="/submit">
            <input type="hidden" name="csrf_token" value="{}" />
            <input type="text" name="data" />
            <input type="submit" value="Submit" />
        </form>
    '''.format(session['csrf_token'])

@app.route('/submit', methods=['POST'])
def submit():
    csrf_token = request.form.get('csrf_token')

    if not csrf_token or csrf_token != session.get('csrf_token'):
        logging.warning("CSRF validation failed")
        return "CSRF validation failed", 400

    # Remove the CSRF token from the session after validation
    session.pop('csrf_token', None)

    data = request.form.get('data')
    # Process the data safely here
    logging.info(f"Data received: {data}")
    return "Data received: {}".format(data)

# Rate limiting (basic example - consider using a library like Flask-Limiter)
RATE_LIMIT = 5  # requests per minute
REQUEST_HISTORY = {}

@app.before_request
def rate_limit():
    ip_address = request.remote_addr
    now = int(time.time())

    if ip_address in REQUEST_HISTORY:
        requests = REQUEST_HISTORY[ip_address]
        requests = [r for r in requests if r > now - 60]  # Keep requests within the last minute
        REQUEST_HISTORY[ip_address] = requests

        if len(requests) >= RATE_LIMIT:
            logging.warning(f"Rate limit exceeded for IP: {ip_address}")
            return "Rate limit exceeded", 429  # Too Many Requests

        requests.append(now)
    else:
        REQUEST_HISTORY[ip_address] = [now]


if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)

