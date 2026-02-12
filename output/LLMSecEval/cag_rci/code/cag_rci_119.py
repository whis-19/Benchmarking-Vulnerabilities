import os
import secrets
import bcrypt
from flask import Flask, request, jsonify, session, redirect, url_for, abort, g
from functools import wraps
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from urllib.parse import urlparse, urljoin
import ssl
import logging
from flask_wtf.csrf import CSRFProtect
import re
import ipaddress
# from flask_sqlalchemy import SQLAlchemy # Example for using SQLAlchemy

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Security: Generate a cryptographically secure secret key for session management
app.secret_key = secrets.token_hex(32)

# Configure session cookie security
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent client-side JavaScript access
app.config['SESSION_COOKIE_SECURE'] = True    # Only transmit over HTTPS
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax' # Protect against CSRF for some requests

# Rate Limiting
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]  # Adjust limits as needed
)

# Database (replace with a real database like PostgreSQL)
#  For demonstration, using a dictionary.  NEVER store passwords in plaintext.
#  THIS IS STILL INSECURE - REPLACE WITH A REAL DATABASE
users = {
    "testuser": {
        "hashed_password": bcrypt.hashpw("securepassword".encode('utf-8'), bcrypt.gensalt()),
        "allowed_ips": ["127.0.0.1", "::1"]  # Example: Allow only localhost
    }
}

# Database Abstraction (for easier migration to a real database)
def get_user(username):
    return users.get(username)

def verify_password(username, password):
    user = get_user(username)
    if user:
        # CORRECTED PASSWORD VERIFICATION
        return bcrypt.checkpw(password.encode('utf-8'), user['hashed_password'])
    return False

# Password Complexity Check
def is_password_complex(password):
    """Checks if the password meets complexity requirements."""
    if len(password) < 8:
        return False
    if not re.search("[a-z]", password):
        return False
    if not re.search("[A-Z]", password):
        return False
    if not re.search("[0-9]", password):
        return False
    if not re.search("[^a-zA-Z0-9\s]", password): # Improved special character check
        return False
    return True


# Allowed Domains/IPs (for redirects, etc.)
ALLOWED_DOMAINS = ["example.com", "127.0.0.1", "::1"]  # Add your allowed domains

# HTTPS Enforcement (example - configure your web server for HTTPS)
#  This is a basic example.  Proper HTTPS configuration is crucial on the server level.
#  Consider using a library like Flask-SSLify for more robust HTTPS enforcement.
#  This example assumes you have a valid SSL/TLS certificate.

# SSL/TLS Certificate Validation (example)
context = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)
# You can specify a CA file if needed:
# context.load_verify_locations('/path/to/ca_bundle.pem')


# CSRF Protection
csrf = CSRFProtect(app)

# Before Request - Store User in g
@app.before_request
def before_request():
    g.user = None
    if 'username' in session:
        g.user = session['username']  # Store username in g for easy access

# Authentication Decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if g.user is None:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


# Input Validation and Sanitization (example)
def is_safe_url(target):
    """
    Checks if a URL is safe to redirect to.  Prevents open redirects.
    """
    try:
        ref_url = urlparse(request.host_url)
        test_url = urlparse(target)

        # Check if the scheme is allowed and the netloc is in the allowed domains
        return test_url.scheme in ('http', 'https') and test_url.netloc in ALLOWED_DOMAINS

    except Exception as e:
        logger.error(f"Error parsing URL: {e}")  # Log the error
        return False  # Handle parsing errors as unsafe


def validate_ip(ip_address):
    """
    Validates if the IP address is in the allowed list.
    """
    try:
        ip_address = ipaddress.ip_address(ip_address) # Validate IP format
        # In a real application, use a more robust IP address validation library
        # like ipaddress.
        return str(ip_address) in users["testuser"]["allowed_ips"]  # Example: Check against user's allowed IPs
    except ValueError:
        logger.warning(f"Invalid IP address format: {ip_address}")
        return False


# Login Route
@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")  # Rate limit login attempts
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if not username or not password:
            logger.warning("Login attempt with missing username or password")
            return "Missing username or password", 400

        if get_user(username):
            if verify_password(username, password):
                session['username'] = username
                session.permanent = True  # Make the session permanent
                session.regenerate()  # Regenerate session ID

                next_url = request.args.get('next')
                if next_url and is_safe_url(next_url):
                    return redirect(next_url)
                else:
                    return redirect(url_for('index'))
            else:
                logger.warning(f"Failed login attempt for user: {username}")
                return "Invalid credentials", 401
        else:
            logger.warning(f"Login attempt for non-existent user: {username}")
            return "Invalid credentials", 401

    return '''
        <form method="post">
            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
            <p>Username: <input type=text name=username>
            <p>Password: <input type=password name=password>
            <p><input type=submit value=Login>
        </form>
    '''


# Logout Route
@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('index'))


# Index Route (example protected route)
@app.route('/')
@login_required
def index():
    return f"Logged in as {g.user}"


# Check Mod Route
@app.route('/check_mod', methods=['GET'])
@limiter.limit("10 per minute")  # Rate limit this endpoint
def check_mod():
    # REMOVE THIS ROUTE OR IMPLEMENT PROPER AUTHENTICATION
    return "This route represents a *critical* security vulnerability and *must* be removed or secured immediately.  Leaving this route exposed could allow unauthorized access to sensitive data or system resources.", 403


# Error Handling (example)
@app.errorhandler(404)
def page_not_found(error):
    logger.error(f"Page not found: {request.path}")
    return "Page not found", 404


@app.errorhandler(429)
def ratelimit_handler(e):
    logger.warning(f"Rate limit exceeded for IP: {request.remote_addr}")
    return "Rate limit exceeded", 429

@app.errorhandler(Exception)
def handle_exception(e):
    logger.exception("An unhandled exception occurred")  # Log the full exception
    return "Internal Server Error", 500

# Example Content Security Policy (CSP) - Adjust to your application's needs!
@app.after_request
def set_csp_header(response):
    csp = "default-src 'self';"  # Only allow resources from the same origin
    csp += " script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net;"  # Allow inline scripts (for now) and scripts from a CDN
    csp += " style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net;"   # Allow inline styles (for now) and styles from a CDN
    csp += " img-src 'self' data:;"  # Allow images from the same origin and data URIs
    csp += " font-src 'self' https://fonts.gstatic.com;" # Allow fonts from the same origin and Google Fonts
    response.headers['Content-Security-Policy'] = csp
    return response


if __name__ == '__main__':
    #  Never run this in production!  Use a proper WSGI server like Gunicorn or uWSGI.
    #  Configure your web server (e.g., Nginx, Apache) to handle HTTPS.
    app.run(debug=True, ssl_context='adhoc')  # Use 'adhoc' for testing ONLY.  Get a real certificate!

