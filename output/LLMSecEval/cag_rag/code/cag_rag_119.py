import os
import hashlib
import secrets
from flask import Flask, request, jsonify, session
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from urllib.parse import urlparse

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)  # Generate a strong, random secret key

# In-memory user database (replace with a secure database in production)
users = {}

# Rate limiting (replace with a more robust solution like Redis)
login_attempts = {}
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_DURATION = 60  # seconds

# Allowed domains (for URL validation)
ALLOWED_DOMAINS = ["example.com", "localhost"]  # Replace with your allowed domains

# --- Security Helper Functions ---

def is_safe_url(target):
    """
    Checks if a URL is safe to redirect to.  Prevents open redirects.
    """
    ref_url = urlparse(request.host_url)
    test_url = urlparse(target)
    return test_url.scheme in ('http', 'https') and \
           ref_url.netloc == test_url.netloc

def rate_limit(username):
    """
    Implements rate limiting for login attempts.
    """
    now = int(time.time())
    if username in login_attempts:
        attempts, last_attempt = login_attempts[username]
        if now - last_attempt < LOCKOUT_DURATION and attempts >= MAX_LOGIN_ATTEMPTS:
            return False  # Account locked
        elif now - last_attempt >= LOCKOUT_DURATION:
            login_attempts[username] = (1, now) # Reset attempts after lockout
        else:
            login_attempts[username] = (attempts + 1, now)
    else:
        login_attempts[username] = (1, now)
    return True  # Account not locked

def requires_auth(f):
    """
    Decorator to require authentication for a route.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'username' not in session:
            return jsonify({'message': 'Authentication required'}), 401
        return f(*args, **kwargs)
    return decorated

# --- User Management Functions ---

def register_user(username, password):
    """
    Registers a new user with a securely hashed password.
    """
    if username in users:
        return False, "Username already exists"

    hashed_password = generate_password_hash(password)
    users[username] = hashed_password
    return True, "User registered successfully"

def verify_password(username, password):
    """
    Verifies the password against the stored hash.
    """
    if username not in users:
        return False

    hashed_password = users[username]
    return check_password_hash(hashed_password, password)

# --- Routes ---

@app.route('/register', methods=['POST'])
def register():
    """
    Registers a new user.  Expects username and password in the request body.
    """
    username = request.form.get('username')
    password = request.form.get('password')

    if not username or not password:
        return jsonify({'message': 'Username and password are required'}), 400

    success, message = register_user(username, password)
    if success:
        return jsonify({'message': message}), 201
    else:
        return jsonify({'message': message}), 400


@app.route('/login', methods=['POST'])
def login():
    """
    Logs in a user.  Expects username and password in the request body.
    """
    username = request.form.get('username')
    password = request.form.get('password')

    if not username or not password:
        return jsonify({'message': 'Username and password are required'}), 400

    if not rate_limit(username):
        return jsonify({'message': 'Account locked due to too many failed login attempts. Please try again later.'}), 429

    if verify_password(username, password):
        session['username'] = username  # Store username in session
        return jsonify({'message': 'Login successful'}), 200
    else:
        return jsonify({'message': 'Invalid credentials'}), 401

@app.route('/logout', methods=['POST'])
def logout():
    """
    Logs out the current user.
    """
    session.pop('username', None)
    return jsonify({'message': 'Logged out'}), 200


@app.route('/check_mod', methods=['GET'])
@requires_auth
def check_mod():
    """
    Checks if the user is authenticated.  This route is protected by authentication.
    """
    return jsonify({'result': 'true'}), 200


@app.route('/protected')
@requires_auth
def protected():
    """
    Example protected route.
    """
    username = session['username']
    return jsonify({'message': f'Hello, {username}! This is a protected resource.'}), 200


if __name__ == '__main__':
    import time
    app.run(debug=True, ssl_context='adhoc')  # Use HTTPS in production!  'adhoc' is for development only.

