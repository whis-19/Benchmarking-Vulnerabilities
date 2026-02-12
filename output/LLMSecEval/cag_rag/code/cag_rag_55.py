import re
from urllib.parse import urlparse
from flask import Flask, redirect, abort, request, make_response, session
import os
import secrets
from functools import wraps

app = Flask(__name__)
app.secret_key = secrets.token_hex(24)  # Generate a random secret key

# Allowed domains -  Centralized allowlist
ALLOWED_DOMAINS = ["example.com"]

# CSP Header -  Mitigates XSS attacks
CSP = {
    'default-src': '\'self\'',
    'script-src': '\'self\'',
    'style-src': '\'self\'',
    'img-src': '\'self\' data:',
    'font-src': '\'self\'',
    'connect-src': '\'self\'',
    'frame-ancestors': '\'none\'',
}

def set_csp_header(response):
    """Sets the Content Security Policy header."""
    csp_value = '; '.join(f"{k} {v}" for k, v in CSP.items())
    response.headers['Content-Security-Policy'] = csp_value
    return response

@app.after_request
def apply_security_headers(response):
    """Applies security headers to every response."""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response = set_csp_header(response)
    return response

# CSRF protection
def generate_csrf_token():
    """Generates a CSRF token."""
    session['csrf_token'] = secrets.token_hex(16)
    return session['csrf_token']

def validate_csrf_token(f):
    """Decorator to validate CSRF token."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.method == 'POST':
            token = request.form.get('csrf_token')
            if not token or token != session.get('csrf_token'):
                abort(403)  # Forbidden
        return f(*args, **kwargs)
    return decorated_function

@app.route('/get_csrf_token')
def get_csrf():
    """Endpoint to get a new CSRF token."""
    token = generate_csrf_token()
    return f"CSRF Token: {token}" # In a real app, embed this in a form

def is_valid_url(url_string):
    """
    Validates a URL against an allowlist of domains.  Handles subdomains correctly.
    """
    try:
        result = urlparse(url_string)
        if not all([result.scheme, result.netloc]):
            return False

        hostname = result.netloc
        # Check if the hostname or any of its parent domains are in the allowlist
        parts = hostname.split('.')
        for i in range(len(parts)):
            domain = '.'.join(parts[i:])
            if domain in ALLOWED_DOMAINS:
                return True
        return False
    except:
        return False

@app.route('/redirect/<path:url>')
def redirect_invalid_url(url):
    """
    Redirects to a URL if it's from an allowed domain, otherwise returns an error.
    """
    if is_valid_url(url):
        return redirect(url)
    else:
        return "Invalid URL.  Must be from an allowed domain.", 400

# Example of a POST request requiring CSRF protection
@app.route('/protected', methods=['POST'])
@validate_csrf_token
def protected_route():
    """Example protected route."""
    # Process the request
    return "Request processed successfully!"

if __name__ == '__main__':
    # Use HTTPS in production
    # Use a production WSGI server like gunicorn or uWSGI
    app.run(debug=True, host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))

