import hashlib
import os
from flask import Flask, request, jsonify, session
from functools import wraps
import secrets  # For generating secure random numbers
import sqlite3  # For database interaction
import logging  # For logging
from werkzeug.security import generate_password_hash, check_password_hash # For secure password hashing

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Generate a random secret key for session management

# Configure session security
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent JavaScript access
app.config['SESSION_COOKIE_SECURE'] = True   # Only transmit over HTTPS (in production)
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax' # Add SameSite attribute for CSRF protection

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

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
            is_moderator INTEGER NOT NULL DEFAULT 0
        )
    ''')
    conn.commit()
    conn.close()

init_db()  # Initialize the database on application startup


# Authentication decorator
def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'username' not in session:
            logging.warning("Unauthorized access attempt to %s", request.path)
            return jsonify({'message': 'Authentication required'}), 401, {'WWW-Authenticate': 'Basic realm="Login Required"'}
        return f(*args, **kwargs)
    return decorated

# Authentication function
def authenticate(username, password):
    """Authenticates a user."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT hashed_password FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    conn.close()

    if user:
        hashed_password = user['hashed_password']
        return check_password_hash(hashed_password, password)
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
        logging.info("User %s is a moderator", username)
        return jsonify({'message': 'User is a moderator'}), 200
    else:
        logging.info("User %s is not a moderator", username)
        return jsonify({'message': 'User is not a moderator'}), 403

@app.route('/login', methods=['POST'])
def login():
    """Logs in a user and sets the session."""
    auth = request.authorization
    if not auth or not authenticate(auth.username, auth.password):
        logging.warning("Failed login attempt for user: %s", auth.username if auth else "Unknown")
        return jsonify({'message': 'Invalid credentials'}), 401, {'WWW-Authenticate': 'Basic realm="Login Required"'}

    session['username'] = auth.username  # Store username in session
    session.regenerate() # Regenerate session ID after login
    logging.info("User %s logged in successfully", auth.username)
    return jsonify({'message': 'Login successful'}), 200

@app.route('/logout', methods=['POST'])
def logout():
    """Logs out a user by clearing the session."""
    username = session.pop('username', None)
    if username:
        logging.info("User %s logged out successfully", username)
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
        logging.warning("Create user request missing username or password")
        return jsonify({'message': 'Username and password are required'}), 400

    # Input validation (example - add more robust validation)
    if len(username) < 3:
        logging.warning("Create user request with invalid username length")
        return jsonify({'message': 'Username must be at least 3 characters'}), 400
    if len(password) < 8:
        logging.warning("Create user request with invalid password length")
        return jsonify({'message': 'Password must be at least 8 characters'}), 400

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
    existing_user = cursor.fetchone()
    if existing_user:
        conn.close()
        logging.warning("Create user request for existing username: %s", username)
        return jsonify({'message': 'Username already exists'}), 409

    # Hash the password securely
    hashed_password = generate_password_hash(password)

    try:
        cursor.execute('''
            INSERT INTO users (username, hashed_password)
            VALUES (?, ?)
        ''', (username, hashed_password))
        conn.commit()
        conn.close()
        logging.info("User %s created successfully", username)
        return jsonify({'message': 'User created successfully'}), 201
    except sqlite3.IntegrityError as e:
        conn.close()
        logging.error("Error creating user %s: %s", username, e)
        return jsonify({'message': 'Username already exists'}), 409
    except Exception as e:
        conn.close()
        logging.exception("Unexpected error creating user %s: %s", username, e)
        return jsonify({'message': 'An unexpected error occurred'}), 500 # Generic error message


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)

