import os
import secrets
import hashlib
from flask import Flask, request, jsonify, session, redirect, url_for, abort
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from urllib.parse import urlparse

app = Flask(__name__)
app.secret_key = secrets.token_hex(24)  # Generate a random secret key

# In-memory user database (replace with a secure database in production)
users = {
    "admin": generate_password_hash("P@$$wOrd")  # Store password hashes, not plain text
}

# Allowed domains/IPs (example)
ALLOWED_DOMAINS = ["example.com", "127.0.0.1"]

# Rate limiting (very basic example - use a proper library like Flask-Limiter in production)
login_attempts = {}
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_DURATION = 60  # seconds

def is_safe_url(target):
    """
    Checks if a URL is safe to redirect to.  Prevents open redirects.
    """
    ref_url = urlparse(request.host_url)
    test_url = urlparse(target)
    return test_url.scheme in ('http', 'https') and \
           ref_url.netloc == test_url.netloc

def limit_login_attempts(username):
    """
    Basic rate limiting for login attempts.
    """
    import time
    now = time.time()
    if username in login_attempts:
        attempts, lockout_start = login_attempts[username]
        if lockout_start and now - lockout_start < LOCKOUT_DURATION:
            return False, LOCKOUT_DURATION - (now - lockout_start)  # Still locked out
        if attempts >= MAX_LOGIN_ATTEMPTS:
            login_attempts[username] = (attempts + 1, now)  # Start lockout
            return False, LOCKOUT_DURATION
        login_attempts[username] = (attempts + 1, None)  # Increment attempts
    else:
        login_attempts[username] = (1, None)  # First attempt
    return True, 0  # Allowed, no lockout

def require_https(func):
    """
    Decorator to enforce HTTPS.
    """
    @wraps(func)
    def wrapper(*args, **kwargs):
        if not request.is_secure:
            return "HTTPS is required", 400
        return func(*args, **kwargs)
    return wrapper

def validate_domain(func):
    """
    Decorator to validate the referring domain.
    """
    @wraps(func)
    def wrapper(*args, **kwargs):
        referrer = request.referrer
        if referrer:
            domain = urlparse(referrer).netloc
            if domain not in ALLOWED_DOMAINS:
                return "Unauthorized domain", 403
        return func(*args, **kwargs)
    return wrapper

@app.route('/login', methods=['POST'])
@require_https
@validate_domain
def login():
    """
    Handles user login.
    """
    username = request.form.get('username')
    password = request.form.get('password')

    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400

    allowed, lockout_time = limit_login_attempts(username)
    if not allowed:
        return jsonify({"error": f"Too many login attempts.  Locked out for {lockout_time:.0f} seconds."}), 429

    if username in users:
        if check_password_hash(users[username], password):
            session['username'] = username  # Store username in session
            login_attempts.pop(username, None)  # Reset attempts on successful login
            return jsonify({"message": "Login successful"})
        else:
            return jsonify({"error": "Invalid credentials"}), 401
    else:
        return jsonify({"error": "Invalid credentials"}), 401

@app.route('/logout')
@require_https
def logout():
    """
    Handles user logout.
    """
    session.pop('username', None)
    return jsonify({"message": "Logged out"})

def login_required(func):
    """
    Decorator to require login.
    """
    @wraps(func)
    def wrapper(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login'))  # Redirect to login page
        return func(*args, **kwargs)
    return wrapper

@app.route('/protected')
@require_https
@login_required
def protected():
    """
    Example protected route.
    """
    return f"Hello, {session['username']}! This is a protected area."

@app.route('/check_mod', methods=['GET'])
@require_https
@validate_domain
def check_mod():
    """
    Checks username and password against stored credentials.  DO NOT PASS CREDENTIALS IN THE URL.
    This example is for demonstration purposes only and should be refactored to use a secure login form.
    """
    # DO NOT DO THIS IN PRODUCTION.  GET requests should not be used for authentication.
    username = request.args.get('username')
    password = request.args.get('password')

    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400

    allowed, lockout_time = limit_login_attempts(username)
    if not allowed:
        return jsonify({"error": f"Too many login attempts.  Locked out for {lockout_time:.0f} seconds."}), 429

    if username in users:
        if check_password_hash(users[username], password):
            login_attempts.pop(username, None)  # Reset attempts on successful login
            return 'true'
        else:
            return 'false'
    else:
        return 'false'

@app.errorhandler(404)
def page_not_found(error):
    return "Page not found", 404

@app.errorhandler(500)
def internal_server_error(error):
    return "Internal server error", 500

if __name__ == '__main__':
    #  DO NOT USE debug=True IN PRODUCTION!
    app.run(debug=False, ssl_context='adhoc') # Use adhoc for testing, replace with real certs in production

