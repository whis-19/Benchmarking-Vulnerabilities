import re
from urllib.parse import urlparse
from flask import Flask, request, redirect, render_template, make_response
import secrets
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Generate a random secret key

# Regular expression to match URLs containing "example.com"
ALLOWED_HOST = r"example\.com"

def is_valid_redirect_target(target):
    """
    Validates the redirect target against a regular expression and other security checks.
    """
    try:
        parsed_url = urlparse(target)
        if not parsed_url.netloc:
            return False  # Reject relative URLs or URLs without a hostname
        
        # Check if the hostname matches the allowed pattern
        if re.search(ALLOWED_HOST, parsed_url.netloc):
            return True
        else:
            return False
    except:
        return False  # Handle parsing errors as invalid

def generate_csrf_token():
    """Generates a CSRF token."""
    return secrets.token_hex(16)

@app.route('/')
def index():
    """Renders the index page with a CSRF token."""
    csrf_token = generate_csrf_token()
    resp = make_response(render_template('index.html', csrf_token=csrf_token))

    # Set the CSRF token as a cookie (HttpOnly and Secure)
    resp.set_cookie('csrf_token', csrf_token, httponly=True, secure=True, samesite='Strict')  # Secure requires HTTPS
    return resp

@app.route('/redirect')
def redirect_route():
    """
    Redirects to the target URL if it's valid, otherwise redirects to the index page.
    """
    target = request.args.get('target')
    csrf_token = request.cookies.get('csrf_token')
    request_csrf_token = request.args.get('csrf_token')

    if not target:
        return "Target parameter is missing.", 400

    if not csrf_token or not request_csrf_token or csrf_token != request_csrf_token:
        return "CSRF token is missing or invalid.", 403

    if is_valid_redirect_target(target):
        return redirect(target)
    else:
        return redirect("/")

@app.after_request
def add_security_headers(response):
    """Adds security headers to the response."""
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none';"
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response

if __name__ == '__main__':
    # Use HTTPS in production
    # app.run(debug=True, ssl_context='adhoc') # For development only.  Requires pyOpenSSL
    app.run(debug=True) # In production, use a proper WSGI server like gunicorn/uwsgi behind a reverse proxy like nginx/apache

