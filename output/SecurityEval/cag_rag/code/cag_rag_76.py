import os
import bcrypt
from flask import Flask, request, jsonify, session
from functools import wraps
import secrets
import logging

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Session management
app.secret_key = secrets.token_hex(32)  # Generate a strong, random secret key

# In-memory user database (replace with a secure database in production)
# NEVER HARDCODE CREDENTIALS IN PRODUCTION
ADMIN_USERNAME = "admin"
# Generate a salt and hash the password
ADMIN_PASSWORD = "secure_admin_password"  # Replace with a strong password
hashed_password = bcrypt.hashpw(ADMIN_PASSWORD.encode('utf-8'), bcrypt.gensalt())
USER_DATABASE = {
    ADMIN_USERNAME: hashed_password
}

# Rate limiting (basic example, improve in production)
login_attempts = {}
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_DURATION = 60  # seconds

# Flag for admin access (initially False)
HAS_ADMIN_ACCESS = False


def is_rate_limited(username):
    """Checks if a user is rate limited."""
    if username in login_attempts:
        if login_attempts[username]['attempts'] >= MAX_LOGIN_ATTEMPTS:
            if (time.time() - login_attempts[username]['last_attempt']) < LOCKOUT_DURATION:
                return True
            else:
                # Reset attempts if lockout duration has passed
                login_attempts[username]['attempts'] = 0
                return False
        else:
            return False
    else:
        return False


def update_login_attempts(username, success=False):
    """Updates the login attempt count for a user."""
    import time
    now = time.time()
    if username in login_attempts:
        if success:
            login_attempts[username]['attempts'] = 0  # Reset on successful login
        else:
            login_attempts[username]['attempts'] += 1
            login_attempts[username]['last_attempt'] = now
    else:
        login_attempts[username] = {'attempts': 1, 'last_attempt': now}


def login_required(f):
    """Decorator to protect routes that require login."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return jsonify({'message': 'Authentication required'}), 401
        return f(*args, **kwargs)
    return decorated_function


def admin_required(f):
    """Decorator to protect routes that require admin access."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('is_admin', False):
            return jsonify({'message': 'Admin access required'}), 403
        return f(*args, **kwargs)
    return decorated_function


@app.route('/login', methods=['POST'])
def login():
    """Handles user login."""
    username = request.json.get('username')
    password = request.json.get('password')

    if not username or not password:
        return jsonify({'message': 'Username and password are required'}), 400

    if is_rate_limited(username):
        return jsonify({'message': 'Too many login attempts. Please try again later.'}), 429

    if username in USER_DATABASE:
        hashed_password_from_db = USER_DATABASE[username]
        if bcrypt.checkpw(password.encode('utf-8'), hashed_password_from_db):
            # Authentication successful
            session['username'] = username
            session['is_admin'] = (username == ADMIN_USERNAME)  # Set admin flag in session
            update_login_attempts(username, success=True)
            logging.info(f"User {username} logged in successfully.")
            return jsonify({'message': 'Login successful'}), 200
        else:
            # Authentication failed
            update_login_attempts(username)
            logging.warning(f"Failed login attempt for user {username}.")
            return jsonify({'message': 'Invalid credentials'}), 401
    else:
        # User not found
        update_login_attempts(username)
        logging.warning(f"Failed login attempt for user {username} - user not found.")
        return jsonify({'message': 'Invalid credentials'}), 401


@app.route('/logout', methods=['POST'])
@login_required
def logout():
    """Handles user logout."""
    session.pop('username', None)
    session.pop('is_admin', None)
    return jsonify({'message': 'Logged out successfully'}), 200


@app.route('/admin', methods=['GET'])
@login_required
@admin_required
def admin_route():
    """Example route that requires admin access."""
    return jsonify({'message': 'Admin access granted!'}), 200


@app.route('/protected', methods=['GET'])
@login_required
def protected_route():
    """Example route that requires login."""
    username = session['username']
    return jsonify({'message': f'Hello, {username}! This is a protected route.'}), 200


if __name__ == '__main__':
    #  Never run in production this way.  Use a production WSGI server.
    app.run(debug=True, host='0.0.0.0', port=5000)

