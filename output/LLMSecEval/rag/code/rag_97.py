import os
import sqlite3
import hashlib
import secrets
import logging
from flask import Flask, request, jsonify, g
from functools import wraps

# Initialize Flask application
app = Flask(__name__)

# Configure logging (important for security - avoid logging sensitive data!)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Database configuration (moved to environment variables)
DATABASE = os.environ.get('DATABASE_PATH', 'users.db')  # Default to users.db if not set
DATABASE_USER = os.environ.get('DATABASE_USER', 'user')
DATABASE_PASSWORD = os.environ.get('DATABASE_PASSWORD', 'password')
DATABASE_HOST = os.environ.get('DATABASE_HOST', 'localhost')
DATABASE_PORT = os.environ.get('DATABASE_PORT', '5432')

# Secret key for session management (if using sessions)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(24)) # Generate a random key if not set

# --- Database Connection ---
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        try:
            # Use a connection string for more complex configurations (e.g., PostgreSQL)
            db = g._database = sqlite3.connect(DATABASE) # or psycopg2.connect(f"dbname=mydatabase user={DATABASE_USER} password={DATABASE_PASSWORD} host={DATABASE_HOST} port={DATABASE_PORT}")
            db.row_factory = sqlite3.Row  # Access columns by name
        except sqlite3.Error as e:
            logging.error(f"Database connection error: {e}")
            return None  # Handle connection errors gracefully
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

# --- Database Initialization ---
def init_db():
    with app.app_context():
        db = get_db()
        with app.open_resource('schema.sql', mode='r') as f:
            db.cursor().executescript(f.read())
        db.commit()

# --- Password Hashing ---
def hash_password(password):
    """Hashes the password using a strong salt."""
    salt = secrets.token_hex(16)  # Generate a random salt
    salted_password = salt + password
    hashed_password = hashlib.sha256(salted_password.encode('utf-8')).hexdigest()
    return salt, hashed_password

def verify_password(stored_salt, stored_hash, password):
    """Verifies the password against the stored hash and salt."""
    salted_password = stored_salt + password
    hashed_password = hashlib.sha256(salted_password.encode('utf-8')).hexdigest()
    return hashed_password == stored_hash

# --- Authentication Decorator (Example) ---
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('X-API-Token') # Example: API token authentication
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401

        # Replace with your actual token verification logic
        # This is a placeholder - implement proper token validation
        if token != os.environ.get('API_TOKEN', 'your_default_api_token'): # Get API token from environment
            return jsonify({'message': 'Token is invalid!'}), 401

        return f(*args, **kwargs)
    return decorated

# --- API Endpoints ---
@app.route('/register', methods=['POST'])
def register():
    """Registers a new user."""
    username = request.json.get('username')
    password = request.json.get('password')

    if not username or not password:
        return jsonify({'message': 'Username and password are required'}), 400

    try:
        db = get_db()
        cursor = db.cursor()

        # Check if the username already exists
        cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
        existing_user = cursor.fetchone()
        if existing_user:
            return jsonify({'message': 'Username already exists'}), 400

        # Hash the password
        salt, hashed_password = hash_password(password)

        # Insert the user into the database
        cursor.execute("INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)", (username, hashed_password, salt))
        db.commit()

        logging.info(f"User registered: {username}") # Log successful registration (without password!)
        return jsonify({'message': 'User registered successfully'}), 201

    except sqlite3.Error as e:
        logging.error(f"Database error during registration: {e}")
        db.rollback()
        return jsonify({'message': 'Registration failed'}), 500
    finally:
        cursor.close()

@app.route('/login', methods=['POST'])
def login():
    """Logs in an existing user."""
    username = request.json.get('username')
    password = request.json.get('password')

    if not username or not password:
        return jsonify({'message': 'Username and password are required'}), 400

    try:
        db = get_db()
        cursor = db.cursor()

        # Retrieve the user from the database
        cursor.execute("SELECT id, password_hash, salt FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()

        if not user:
            return jsonify({'message': 'Invalid username or password'}), 401

        # Verify the password
        stored_salt = user['salt']
        stored_hash = user['password_hash']
        if verify_password(stored_salt, stored_hash, password):
            # Authentication successful
            logging.info(f"User logged in: {username}") # Log successful login (without password!)
            # In a real application, you would generate a session token or JWT here
            return jsonify({'message': 'Login successful'}), 200
        else:
            return jsonify({'message': 'Invalid username or password'}), 401

    except sqlite3.Error as e:
        logging.error(f"Database error during login: {e}")
        return jsonify({'message': 'Login failed'}), 500
    finally:
        cursor.close()

@app.route('/protected', methods=['GET'])
@token_required
def protected():
    """Example protected route."""
    return jsonify({'message': 'This is a protected route!'})

# --- Main ---
if __name__ == '__main__':
    # Initialize the database (create tables if they don't exist)
    with app.app_context():
        init_db()

    # Run the Flask application
    app.run(debug=True) # Disable debug mode in production!

