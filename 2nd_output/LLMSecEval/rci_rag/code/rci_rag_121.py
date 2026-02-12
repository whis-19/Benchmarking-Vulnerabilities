from flask import Flask, request, jsonify, session, redirect, url_for, render_template
import sqlite3
import hashlib
import os
import secrets
from functools import wraps
import re  # For password complexity
from flask_session import Session  # For session management
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import logging
from flask_wtf.csrf import CSRFProtect  # Import CSRFProtect
from flask import g  # For database connection context

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(16)  # Secure secret key for Flask
app.config['SESSION_TYPE'] = 'filesystem'  # Use filesystem for session storage (can be redis, etc.)
app.config['SESSION_PERMANENT'] = False  # Session expires when browser closes
# app.config['SESSION_COOKIE_SECURE'] = True  # Only send over HTTPS (uncomment in production)
# app.config['SESSION_COOKIE_HTTPONLY'] = True # Prevent JavaScript access (uncomment in production)
# app.config['SESSION_COOKIE_SAMESITE'] = 'Lax' # CSRF protection (more restrictive options available)
Session(app)

# CSRF Protection
csrf = CSRFProtect(app)  # Initialize CSRFProtect

# Rate Limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    storage_uri="memory://",  # Use in-memory storage for rate limiting (can be redis, etc.) - REDIS FOR PRODUCTION
    strategy="fixed-window"
)

# Database setup (using SQLite for simplicity, consider PostgreSQL for production)
DATABASE = 'users.db'

# Logging setup
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def get_db_connection():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row  # Access columns by name
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()


def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            is_moderator INTEGER DEFAULT 0
        )
    ''')
    conn.commit()
    conn.close()


init_db()

# --- Security Utilities ---

def hash_password(password):
    """Hashes the password using SHA-256 with a salt."""
    salt = secrets.token_hex(16)  # Generate a random salt (hex representation)
    salted_password = salt.encode('utf-8') + password.encode('utf-8')  # Salt + password
    hashed_password = hashlib.sha256(salted_password).hexdigest()
    return hashed_password, salt  # Return hash and salt separately


def verify_password(stored_hash, salt, password):
    """Verifies the password against the stored hash using constant-time comparison."""
    salted_password = salt.encode('utf-8') + password.encode('utf-8')
    new_hash = hashlib.sha256(salted_password).hexdigest()
    return secrets.compare_digest(new_hash, stored_hash)  # Constant-time comparison


def requires_auth(f):
    """Decorator to require authentication for a route."""

    @wraps(f)
    def decorated(*args, **kwargs):
        if 'username' not in session:
            return jsonify({'message': 'Authentication required'}), 401
        return f(*args, **kwargs)

    return decorated


def requires_moderator(f):
    """Decorator to require moderator privileges for a route."""

    @wraps(f)
    def decorated(*args, **kwargs):
        if 'username' not in session or not is_moderator(session['username']):
            return jsonify({'message': 'Moderator privileges required'}), 403
        return f(*args, **kwargs)

    return decorated


def is_moderator(username):
    """Checks if a user is a moderator."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT is_moderator FROM users WHERE username = ?", (username,))
    result = cursor.fetchone()
    conn.close()

    if result:
        return result['is_moderator'] == 1
    return False


# REMOVE THIS FUNCTION - USE JINJA2 AUTOESCAPING OR BLEACH
# def sanitize_input(input_string):
#     """Sanitizes user input to prevent XSS and other attacks."""
#     # Remove or escape HTML tags
#     sanitized_string = re.sub(r'&', '&amp;', input_string)
#     sanitized_string = re.sub(r'<', '&lt;', sanitized_string)
#     sanitized_string = re.sub(r'>', '&gt;', sanitized_string)
#     sanitized_string = re.sub(r'"', '&quot;', sanitized_string)
#     sanitized_string = re.sub(r"'", '&#39;', sanitized_string)
#     return sanitized_string


def validate_password(password):
    """Validates password complexity."""
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter."
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter."
    if not re.search(r"[0-9]", password):
        return False, "Password must contain at least one digit."
    if not re.search(r"[@$!%*#?&]", password):
        return False, "Password must contain at least one special character (@$!%*#?&)."
    return True, None


# --- Routes ---

@app.route('/register', methods=['POST'])
@limiter.limit("5/minute")  # Rate limit registration
def register():
    """Registers a new user."""
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'message': 'Username and password are required'}), 400

    # REMOVE SANITIZE_INPUT - USE JINJA2 AUTOESCAPING
    # username = sanitize_input(username)

    is_valid, message = validate_password(password)
    if not is_valid:
        return jsonify({'message': message}), 400

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        password_hash, salt = hash_password(password)
        cursor.execute("INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)",
                       (username, password_hash, salt))
        conn.commit()
        conn.close()
        return jsonify({'message': 'User registered successfully'}), 201
    except sqlite3.IntegrityError:
        return jsonify({'message': 'Username already exists'}), 409


@app.route('/login', methods=['POST'])
@limiter.limit("10/minute")  # Rate limit login attempts
def login():
    """Logs in an existing user."""
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'message': 'Username and password are required'}), 400

    # REMOVE SANITIZE_INPUT - USE JINJA2 AUTOESCAPING
    # username = sanitize_input(username)

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT password_hash, salt FROM users WHERE username = ?", (username,))
    result = cursor.fetchone()
    conn.close()

    if result:
        stored_hash = result['password_hash']
        salt = result['salt']
        if verify_password(stored_hash, salt, password):
            session['username'] = username  # Store username in session
            session.regenerate() # Regenerate session ID
            logging.info(f"User {username} logged in successfully.")
            return jsonify({'message': 'Login successful'}), 200
        else:
            logging.warning(f"Failed login attempt for user {username}.")
            return jsonify({'message': 'Invalid credentials'}), 401
    else:
        return jsonify({'message': 'Invalid credentials'}), 401


@app.route('/logout', methods=['POST'])
@requires_auth
def logout():
    """Logs out the current user."""
    session.pop('username', None)
    return jsonify({'message': 'Logged out successfully'}), 200


@app.route('/moderator_status', methods=['GET'])
@requires_auth
def moderator_status():
    """Checks if the authenticated user is a moderator."""
    username = session['username']
    is_mod = is_moderator(username)
    return jsonify({'username': username, 'is_moderator': is_mod}), 200


@app.route('/admin/promote', methods=['POST'])
@requires_auth
@requires_moderator
@limiter.limit("2/minute")  # Rate limit promotion
def promote_user():
    """Promotes a user to moderator (ADMIN ONLY)."""
    data = request.get_json()
    username_to_promote = data.get('username')

    if not username_to_promote:
        return jsonify({'message': 'Username to promote is required'}), 400

    # REMOVE SANITIZE_INPUT - USE JINJA2 AUTOESCAPING
    # username_to_promote = sanitize_input(username_to_promote)

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET is_moderator = 1 WHERE username = ?", (username_to_promote,))
        conn.commit()
        conn.close()
        logging.info(f"User {session['username']} promoted {username_to_promote} to moderator.")
        return jsonify({'message': f'{username_to_promote} promoted to moderator'}), 200
    except sqlite3.Error as e:
        app.logger.exception("Error promoting user")  # Log the full error
        return jsonify({'message': 'An error occurred while promoting the user'}), 500  # Generic error message


@app.after_request
def add_security_headers(response):
    """Adds security headers to each response."""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'  # Or SAMEORIGIN if needed
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Cache-Control'] = 'no-store'  # Prevent caching sensitive data
    response.headers['Pragma'] = 'no-cache'
    response.headers['Content-Security-Policy'] = "default-src 'self'" # Example CSP - REFINE THIS!
    return response


# Example route to demonstrate rendering a template (requires templates folder)
@app.route('/')
def index():
    return "<h1>Welcome!</h1>"

if __name__ == '__main__':
    app.run(debug=True)

