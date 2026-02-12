import re
import secrets
from urllib.parse import urlparse

from flask import Flask, request, redirect, render_template, make_response, session

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)  # Replace with a strong, randomly generated key

ALLOWED_DOMAINS = ["example.com"]  # Define allowed domains
CSP_POLICY = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; frame-ancestors 'none';"


def is_safe_url(target):
    """
    Validates the target URL against allowed domains and a regular expression.
    Handles arbitrary subdomain sequences correctly.
    """
    try:
        parsed_url = urlparse(target)
        hostname = parsed_url.hostname
        if not hostname:
            return False  # Reject URLs without a hostname

        # Check against allowed domains, handling subdomains
        if not any(hostname.endswith(domain) for domain in ALLOWED_DOMAINS):
            return False

        # Regular expression to match URLs containing "example.com"
        regex = r"^(https?://)?([a-zA-Z0-9.-]+\.)*example\.com(/.*)?$"
        return re.match(regex, target) is not None

    except Exception:
        return False  # Handle parsing errors as unsafe


def generate_csrf_token():
    """Generates a CSRF token and stores it in the session."""
    token = secrets.token_hex(16)
    session['csrf_token'] = token
    return token


def validate_csrf_token(token):
    """Validates the CSRF token against the one stored in the session."""
    return 'csrf_token' in session and session['csrf_token'] == token


@app.before_request
def before_request():
    """Set Content Security Policy header."""
    response = make_response()
    response.headers['Content-Security-Policy'] = CSP_POLICY


@app.route('/')
def index():
    """Renders the index page with a CSRF token."""
    csrf_token = generate_csrf_token()
    return render_template('index.html', csrf_token=csrf_token)


@app.route('/redirect', methods=['POST'])
def redirect_route():
    """
    Redirects to the target URL if it's safe and the CSRF token is valid.
    Uses POST method to prevent accidental redirects.
    """
    if request.method == 'POST':
        target = request.form.get('target')
        csrf_token = request.form.get('csrf_token')

        if not validate_csrf_token(csrf_token):
            return "CSRF token is invalid.", 400

        if target:
            if is_safe_url(target):
                return redirect(target)
            else:
                return redirect("/")  # Redirect to home if unsafe
        else:
            return "Target URL is missing.", 400
    else:
        return "Method not allowed. Use POST.", 405


@app.after_request
def add_csrf_cookie(response):
    """Adds the CSRF token as a double-submitted cookie."""
    if 'csrf_token' in session:
        response.set_cookie('csrf_token', session['csrf_token'], httponly=True, secure=True)  # Secure flag for HTTPS
    return response


if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=443, ssl_context='adhoc') #Enforce HTTPS

