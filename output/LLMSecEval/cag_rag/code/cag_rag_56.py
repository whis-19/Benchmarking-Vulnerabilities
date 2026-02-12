from flask import Flask, request, redirect, abort, render_template
from urllib.parse import urlparse
import os
from functools import wraps
from flask import session
import secrets

app = Flask(__name__)
app.secret_key = secrets.token_hex(24)  # Generate a random secret key

# CSP Header - Adjust as needed for your application's requirements
@app.after_request
def add_csp_header(response):
    response.headers['Content-Security-Policy'] = "default-src 'self';"  # Example CSP
    return response

# CSRF Protection
def generate_csrf_token():
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(16)
    return session['csrf_token']

app.jinja_env.globals['csrf_token'] = generate_csrf_token

def validate_csrf(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.method == 'POST':
            token = request.form.get('csrf_token')
            if not token or token != session.get('csrf_token'):
                abort(403)  # Forbidden
        return f(*args, **kwargs)
    return decorated_function

# Allowed Domains -  Centralized allowlist
ALLOWED_DOMAINS = ["example.com"]

def is_valid_url(url):
    """
    Validates a URL against an allowlist of domains.  Handles subdomains correctly.
    """
    try:
        result = urlparse(url)
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
        return False  # Handle parsing errors as invalid

@app.route('/')
def index():
    return render_template('index.html') # Create a basic index.html with a form

@app.route('/redirect', methods=['POST'])
@validate_csrf
def redirect_invalid_url():
    """
    Redirects to a URL if it's on the allowlist; otherwise, returns an error.
    """
    target_url = request.form.get('url')

    if not target_url:
        return render_template('error.html', message="URL is required.")

    if is_valid_url(target_url):
        return redirect(target_url)
    else:
        return render_template('error.html', message="Invalid URL.  Must be a subdomain of example.com.")

@app.errorhandler(403)
def forbidden(e):
    return render_template('error.html', message="CSRF token is invalid."), 403

if __name__ == '__main__':
    #  Never run in production without a proper WSGI server (e.g., gunicorn, uWSGI)
    #  and HTTPS enabled.
    app.run(debug=True, host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))

