import os
import sqlite3
from flask import Flask, request, jsonify, abort
from werkzeug.security import generate_password_hash, check_password_hash
import logging
from functools import wraps
from datetime import datetime

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- Configuration ---
DATABASE_PATH = os.environ.get("DATABASE_PATH")
SECRET_KEY = os.environ.get("SECRET_KEY")

if not DATABASE_PATH:
    logging.error("DATABASE_PATH environment variable not set.")
    raise ValueError("DATABASE_PATH environment variable must be set.")
if not SECRET_KEY:
    logging.error("SECRET_KEY environment variable not set.")
    raise ValueError("SECRET_KEY environment variable must be set.")

app.config['SECRET_KEY'] = SECRET_KEY  # For session management (if implemented later)

# --- Database Initialization ---
def get_db_connection():
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row  # Access columns by name
    return conn

def init_db():
    conn = get_db_connection()
    try:
        with open('schema.sql') as f:
            conn.executescript(f.read())
        conn.commit()
        logging.info("Database initialized successfully.")
    except Exception as e:
        logging.error(f"Error initializing database: {e}")
    finally:
        conn.close()

# Create the database and initial moderator if it doesn't exist.  Call this ONCE.
with app.app_context():
    try:
        init_db()
    except ValueError as e:
        print(f"Error during initialization: {e}")
        # Handle the error appropriately, e.g., exit the application
        exit(1)


# --- Authentication ---
def check_moderator(username, password):
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT password FROM moderators WHERE username = ?", (username,))
        result = cursor.fetchone()
        if result:
            stored_password_hash = result['password']
            return check_password_hash(stored_password_hash, password)
        else:
            return False
    except sqlite3.Error as e:
        logging.error(f"Database error during authentication: {e}")
        return False
    finally:
        conn.close()


def create_initial_moderator(username, password):
    conn = get_db_connection()
    try:
        hashed_password = generate_password_hash(password)
        cursor = conn.cursor()
        cursor.execute("INSERT INTO moderators (username, password) VALUES (?, ?)", (username, hashed_password))
        conn.commit()
        logging.info(f"Moderator '{username}' created successfully.")
        return True
    except sqlite3.IntegrityError:
        logging.warning(f"Moderator '{username}' already exists.")
        return False
    except sqlite3.Error as e:
        logging.error(f"Database error during moderator creation: {e}")
        return False
    finally:
        conn.close()


# --- Authentication Decorator ---
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('X-API-Token')  # Example: Using a custom header
        if not token:
            logging.warning("Authentication token missing.")
            abort(401)  # Unauthorized

        # Replace with your actual token validation logic
        if token != "YOUR_SECURE_API_TOKEN":  # NEVER hardcode tokens in production!
            logging.warning("Invalid authentication token.")
            abort(401)

        return f(*args, **kwargs)
    return decorated


# --- Routes ---
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    if not data or 'username' not in data or 'password' not in data:
        logging.warning("Login attempt with missing credentials.")
        return jsonify({'message': 'Missing credentials'}), 400

    username = data['username']
    password = data['password']

    # Input Validation (Length Limits)
    if len(username) > 50:
        return jsonify({'message': 'Username too long'}), 400
    if len(password) > 100:  # Adjust as needed
        return jsonify({'message': 'Password too long'}), 400

    if check_moderator(username, password):
        logging.info(f"Successful login for user: {username}")
        return jsonify({'message': 'Login successful'}), 200
    else:
        logging.warning(f"Failed login attempt for user: {username}")
        return jsonify({'message': 'Invalid credentials'}), 401


@app.route('/admin/create_moderator', methods=['POST'])
@token_required  # Protect with authentication
#@limiter.limit("5/minute")  # Example rate limiting (requires Flask-Limiter)
def create_moderator():
    data = request.get_json()
    if not data or 'username' not in data or 'password' not in data:
        logging.warning("Create moderator attempt with missing credentials.")
        return jsonify({'message': 'Missing credentials'}), 400

    username = data['username']
    password = data['password']

    # Input Validation (Length Limits)
    if len(username) > 50:
        return jsonify({'message': 'Username too long'}), 400
    if len(password) > 100:  # Adjust as needed
        return jsonify({'message': 'Password too long'}), 400

    if create_initial_moderator(username, password):
        return jsonify({'message': 'Moderator created successfully'}), 201
    else:
        return jsonify({'message': 'Moderator creation failed (username might exist)'}), 400


@app.route('/protected', methods=['GET'])
@token_required
def protected():
    return jsonify({'message': 'This is a protected route'}), 200


# --- Error Handling ---
@app.errorhandler(400)
def bad_request(error):
    logging.warning(f"Bad Request: {error}")
    return jsonify({'message': 'Bad Request'}), 400

@app.errorhandler(401)
def unauthorized(error):
    logging.warning(f"Unauthorized: {error}")
    return jsonify({'message': 'Unauthorized'}), 401

@app.errorhandler(500)
def internal_server_error(error):
    logging.error(f"Internal Server Error: {error}")
    return jsonify({'message': 'Internal Server Error'}), 500


# --- Main ---
if __name__ == '__main__':
    # DO NOT USE debug=True IN PRODUCTION!
    if app.debug:
        logging.warning("Debug mode is enabled.  Disable in production!")

    # Reminder:  Use HTTPS in production!
    logging.info("Application starting...")
    app.run(debug=True, host='0.0.0.0', port=5000)
    logging.info("Application stopped.")

