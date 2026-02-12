import hashlib
import os
from flask import Flask, request, jsonify, session
from functools import wraps
import secrets  # For generating secure random numbers
import sqlite3  # For database interaction
import logging
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from markupsafe import escape  # For sanitizing user input

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Secret Key Management
def load_secret_key(filepath="secret_key.txt"):
    """Loads the secret key from a file or generates a new one if it doesn't exist."""
    try:
        with open(filepath, "r") as f:
            return f.read().strip()
    except FileNotFoundError:
        key = os.urandom(24).hex()  # Generate a hex-encoded key
        with open(filepath, "w") as f:
            f.write(key)
        return key

app.secret_key = load_secret_key()  # Load secret key from file

# Session Cookie Configuration
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = True  # Only enable in production with HTTPS
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # Recommended for CSRF protection

# Database setup (using SQLite for simplicity - consider PostgreSQL for production)
DATABASE = 'users.db'

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row  # Access columns by name
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            hashed_password TEXT NOT NULL,
            salt TEXT NOT NULL,
            is_moderator INTEGER NOT NULL DEFAULT 0
        )
    ''')
    conn.commit()
    conn.close()

init_db()  # Initialize the database on application startup


# Function to generate a secure salt
def generate_salt():
    return secrets.token_hex(16)  # 16 bytes = 128 bits, hex encoded

# Function to hash a password
def hash_password(password, salt):
    """Hashes a password using PBKDF2-HMAC with a unique salt."""
    return hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), 100000).hex()

# Function to verify a password against a stored hash
def verify_password(password, hashed_password, salt):
    """Verifies a password against a stored hash."""
    hashed_attempt = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), 100000).hex()
    return hashed_attempt == hashed_password

# Authentication decorator
def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'username' not in session:
            logging.warning("Unauthorized access attempt.")
            return jsonify({'message': 'Authentication required'}), 401, {'WWW-Authenticate': 'Basic realm="Login Required"'}
        return f(*args, **kwargs)
    return decorated

# Authentication function
def authenticate(username, password):
    """Authenticates a user."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT hashed_password, salt FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    conn.close()

    if user:
        hashed_password = user['hashed_password']
        salt = user['salt']
        return verify_password(password, hashed_password, salt)
    return False

# Authorization function (checks if user is a moderator)
def auth_mod(username):
    """Checks if a user is a moderator based on their session."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT is_moderator FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    conn.close()

    if user:
        return user['is_moderator'] == 1  # Assuming 1 represents True
    return False

@app.route('/check_mod', methods=['GET'])
@requires_auth
def check_mod():
    """
    Checks if the user is a moderator.  Requires authentication.
    """
    username = session['username']
    if auth_mod(username):
        return jsonify({'message': 'User is a moderator'}), 200
    else:
        return jsonify({'message': 'User is not a moderator'}), 403

# Rate Limiting
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]  # Example limits
)

@app.route('/login', methods=['POST'])
@limiter.limit("5 per minute")  # Limit login attempts
def login():
    """Logs in a user and sets the session."""
    auth = request.authorization
    if not auth or not authenticate(auth.username, auth.password):
        logging.warning(f"Failed login attempt for user: {auth.username if auth else 'Unknown'}")
        return jsonify({'message': 'Invalid credentials'}), 401, {'WWW-Authenticate': 'Basic realm="Login Required"'}

    session['username'] = auth.username  # Store username in session
    logging.info(f"User {auth.username} logged in successfully.")
    return jsonify({'message': 'Login successful'}), 200

@app.route('/logout', methods=['POST'])
@requires_auth
def logout():
    """Logs out a user by clearing the session."""
    username = session.get('username')
    session.pop('username', None)
    logging.info(f"User {username} logged out successfully.")
    return jsonify({'message': 'Logged out successfully'}), 200

# Example route to create a new user (for initial setup - remove or secure in production)
@app.route('/create_user', methods=['POST'])
def create_user():
    """
    Creates a new user.  This route should be removed or heavily secured in production.
    """
    username = request.json.get('username')
    password = request.json.get('password')

    if not username or not password:
        logging.warning("Create user request missing username or password.")
        return jsonify({'message': 'Username and password are required'}), 400

    # Input validation (example - add more robust validation)
    if len(username) < 3 or len(password) < 8:
        logging.warning(f"Invalid username or password length for user: {username}")
        return jsonify({'message': 'Username must be at least 3 characters and password at least 8 characters'}), 400

    # Sanitize input
    username = escape(username)

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
    existing_user = cursor.fetchone()
    if existing_user:
        conn.close()
        logging.warning(f"Attempt to create user with existing username: {username}")
        return jsonify({'message': 'Username already exists'}), 409

    # Generate a unique salt for the user
    salt = generate_salt()
    hashed_password = hash_password(password, salt)

    try:
        cursor.execute('''
            INSERT INTO users (username, hashed_password, salt)
            VALUES (?, ?, ?)
        ''', (username, hashed_password, salt))
        conn.commit()
        conn.close()
        logging.info(f"User {username} created successfully.")
        return jsonify({'message': 'User created successfully'}), 201
    except sqlite3.IntegrityError:
        conn.close()
        logging.error(f"Integrity error while creating user: {username}", exc_info=True) # Log the full exception
        return jsonify({'message': 'Username already exists'}), 409

# Error Handling
@app.errorhandler(404)
def not_found(error):
    logging.warning(f"404 Not Found: {request.path}")
    return jsonify({'message': 'Not found'}), 404

@app.errorhandler(500)
def internal_server_error(error):
    logging.error("Internal Server Error", exc_info=True)  # Log the full exception
    return jsonify({'message': 'Internal server error'}), 500

@app.errorhandler(429)
def ratelimit_handler(e):
    logging.warning(f"Rate limit exceeded for IP: {get_remote_address()}")
    return jsonify({"message": "Rate limit exceeded. Please try again later."}), 429

if __name__ == '__main__':
    # Rotate Secret Key (Example - implement a more robust rotation mechanism)
    # if os.path.exists("secret_key.txt") and os.stat("secret_key.txt").st_size > 1024: # Example condition
    #     app.secret_key = load_secret_key()
    #     logging.info("Secret key rotated.")

    app.run(debug=True, host='0.0.0.0', port=5000)

