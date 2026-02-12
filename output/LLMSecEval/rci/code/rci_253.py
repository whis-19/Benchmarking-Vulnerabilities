import secrets
import bcrypt
from flask import Flask, request, jsonify, session
from functools import wraps
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
import logging
from datetime import timedelta
import os

# Configure logging
logging.basicConfig(level=logging.INFO,  # Set desired logging level
                    format='%(asctime)s - %(levelname)s - %(message)s')

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(32)  # Securely generate a secret key
app.config['SESSION_COOKIE_SECURE'] = True  # Only send cookies over HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent JavaScript access to cookies
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # Protect against CSRF
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)  # Session timeout
csrf = CSRFProtect(app)

# Rate limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],  # Adjust limits as needed
    storage_uri="memory://"  # Use a more persistent storage in production (e.g., Redis)
)

# In-memory storage for demonstration purposes only.
# **NEVER** store credentials like this in a real application.
# Use a proper database with password hashing.
MODERATORS = {
    "moderator1": {
        "hashed_password": bcrypt.hashpw("password123".encode('utf-8'), bcrypt.gensalt()),
    },
    "moderator2": {
        "hashed_password": bcrypt.hashpw("secure_pass".encode('utf-8'), bcrypt.gensalt()),
    }
}


def get_hashed_password_from_db(username):
    """
    Retrieves the hashed password from the in-memory store.
    **REPLACE WITH DATABASE LOOKUP IN PRODUCTION**
    """
    if username in MODERATORS:
        return MODERATORS[username]["hashed_password"]
    return None


def auth_mod(username, password):
    """Authenticates a moderator."""
    if not username or not password:
        return False  # Prevent empty credentials

    hashed_password = get_hashed_password_from_db(username)
    if hashed_password:
        try:
            if bcrypt.checkpw(password.encode('utf-8'), hashed_password):
                return True
            else:
                return False # Explicitly return False for incorrect password
        except ValueError as e:
            logging.error(f"bcrypt.checkpw error: {e}")
            return False # Handle potential bcrypt errors
    return False


def require_auth(f):
    """Decorator to require authentication for a route."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return jsonify({"error": "Authentication required"}), 401
        return f(*args, **kwargs)
    return decorated_function


@app.route('/login', methods=['POST'])
@limiter.limit("5 per minute")  # Rate limit login attempts
def login():
    """Handles user login."""
    username = request.form.get('username')
    password = request.form.get('password')

    if not username or not password:
        logging.warning("Login attempt with missing username or password")
        return jsonify({"error": "Username and password are required"}), 400

    if username in MODERATORS:
        if auth_mod(username, password):
            session['username'] = username  # Store username in session
            session.regenerate()  # Regenerate the session ID
            logging.info(f"User {username} logged in successfully")
            return jsonify({"message": "Login successful"}), 200
        else:
            logging.warning(f"Failed login attempt for user {username}")
            return jsonify({"error": "Invalid credentials"}), 401
    else:
        logging.warning(f"Login attempt with invalid username: {username}")
        return jsonify({"error": "Invalid credentials"}), 401


@app.route('/logout')
def logout():
    """Handles user logout."""
    if 'username' in session:
        username = session['username']
        logging.info(f"User {username} logged out")
    else:
        logging.info("Logout called without active session")
    session.clear()  # Remove all session data
    session.regenerate()  # Regenerate the session ID
    return jsonify({"message": "Logged out successfully"}), 200


@app.route('/check_mod', methods=['GET'])
@require_auth
def check_mod():
    """Checks if the user is a moderator."""
    username = session.get('username')
    is_moderator = username in MODERATORS  # Or query the database

    return jsonify({"is_moderator": is_moderator}), 200


@app.errorhandler(500)
def internal_server_error(e):
    """Handles internal server errors."""
    logging.exception("Internal Server Error")  # Log the full exception
    return jsonify({"error": "An internal server error occurred"}), 500


if __name__ == '__main__':
    # Determine the port
    port = int(os.environ.get('PORT', 5000))
    app.run(debug=True, ssl_context='adhoc', host='0.0.0.0', port=port)  # Enable SSL for local testing

