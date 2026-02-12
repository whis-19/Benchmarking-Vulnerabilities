import re
import secrets
from urllib.parse import urlparse

from flask import Flask, request, redirect, render_template, make_response, session

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)  # Replace with a strong, randomly generated key

ALLOWED_DOMAINS = ["example.com"]  # Define allowed domains
TARGET_REGEX = re.compile(r"example\.com")  # Matches any URL containing example.com

def is_safe_url(target):
    """
    Validates the target URL against allowed domains and a regular expression.
    Handles arbitrary subdomain sequences correctly.
    """
    try:
        parsed_url = urlparse(target)
        if not parsed_url.netloc:
            return False  # Reject relative URLs or URLs without a netloc
        
        # Extract the domain and handle subdomains
        domain = parsed_url.netloc
        if ":" in domain:
            domain = domain.split(":")[0] # Remove port if present

        # Check against allowlist
        if domain not in ALLOWED_DOMAINS and not any(domain.endswith("." + allowed_domain) for allowed_domain in ALLOWED_DOMAINS):
            return False

        # Check against regex
        if not TARGET_REGEX.search(target):
            return False

        return True
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

@app.route('/')
def index():
    """Renders the index page with a CSRF token."""
    csrf_token = generate_csrf_token()
    response = make_response(render_template('index.html', csrf_token=csrf_token))
    response.headers['Content-Security-Policy'] = "default-src 'self'"  # CSP header
    return response

@app.route('/redirect', methods=['POST'])
def redirect_target():
    """
    Redirects to the target URL if it's safe, otherwise redirects to /.
    Implements CSRF protection.
    """
    if request.method == 'POST':
        target = request.form.get('target')
        csrf_token = request.form.get('csrf_token')

        if not csrf_token or not validate_csrf_token(csrf_token):
            return "CSRF token validation failed.", 400

        if target:
            if is_safe_url(target):
                return redirect(target)
            else:
                return redirect("/")
        else:
            return redirect("/")
    else:
        return "Method not allowed", 405


@app.after_request
def add_security_headers(response):
    """Adds security headers to every response."""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=443, ssl_context='adhoc') # Enforce HTTPS.  'adhoc' is for testing only.  Use proper certificates in production.

