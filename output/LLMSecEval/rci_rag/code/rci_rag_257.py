import os
import secrets
import hashlib
import functools
import logging
from flask import Flask, request, jsonify, g, session, render_template
import pyodbc  # Or your preferred database library
from dotenv import load_dotenv
from flask_wtf.csrf import CSRFProtect, generate_csrf
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_session import Session
import redis
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
import re

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)

# --- Security Configuration ---
MAX_CONNECTIONS = 10  # Limit the number of database connections
SALT_LENGTH = 16  # Length of the salt used for password hashing
SESSION_EXPIRY = 3600  # Session expiry time in seconds (1 hour)

# --- Flask Configuration ---
app.config['SECRET_KEY'] = os.environ.get("FLASK_SECRET_KEY", secrets.token_hex(24))  # Use a strong, randomly generated secret key
app.config['SESSION_TYPE'] = 'redis'
app.config['SESSION_PERMANENT'] = True
app.config['SESSION_USE_SIGNER'] = True  # Optional, but recommended
app.config['SESSION_KEY_PREFIX'] = 'session:'  # Optional prefix for Redis keys
app.config['SESSION_REDIS'] = redis.Redis(host='localhost', port=6379, db=0)  # Redis connection details
app.config['PERMANENT_SESSION_LIFETIME'] = SESSION_EXPIRY
csrf = CSRFProtect(app)  # Enable CSRF protection
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],  # Example rate limits
    storage_uri="redis://localhost:6379"  # Use Redis for production rate limiting
)

# Initialize Flask-Session
sess = Session(app)

# --- Logging Configuration ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- Database Configuration (Read from Environment Variables) ---
#  IMPORTANT:  Never hardcode credentials in your code.  Use environment variables.

def get_db_driver():
    """Returns the database driver from environment variables."""
    driver = os.environ.get("DB_DRIVER")
    if not driver:
        raise ValueError("DB_DRIVER environment variable not set.")
    return driver

def get_server_name():
    """Returns the server name from environment variables."""
    server = os.environ.get("DB_SERVER")
    if not server:
        raise ValueError("DB_SERVER environment variable not set.")
    return server

def get_database_name():
    """Returns the database name from environment variables."""
    database = os.environ.get("DB_NAME")
    if not database:
        raise ValueError("DB_NAME environment variable not set.")
    return database

def get_database_user():
    """Returns the database user from environment variables."""
    user = os.environ.get("DB_USER")
    if not user:
        raise ValueError("DB_USER environment variable not set.")
    return user

def get_database_password():
    """Returns the database password from environment variables."""
    password = os.environ.get("DB_PASSWORD")
    if not password:
        raise ValueError("DB_PASSWORD environment variable not set.")
    return password

# --- SQLAlchemy Database Connection Pooling ---
DATABASE_URL = f"mssql+pyodbc://{get_database_user()}:{get_database_password()}@{get_server_name()}/{get_database_name()}?driver={get_db_driver()}"
engine = create_engine(DATABASE_URL, pool_size=MAX_CONNECTIONS, max_overflow=0)  # Limit pool size
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def get_db():
    """Gets a database session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# --- Input Validation ---
def validate_input(data, expected_keys):
    """
    Validates that the input data contains the expected keys and that the values
    are of the correct type (string in this example).  Adapt to your specific needs.
    Also performs basic sanitization.
    """
    if not isinstance(data, dict):
        return False, "Input must be a JSON object."

    for key in expected_keys:
        if key not in data:
            return False, f"Missing key: {key}"
        if not isinstance(data[key], str):  # Example:  Require strings
            return False, f"Invalid type for key: {key}. Expected string."
        if not data[key]: # Check for empty strings
            return False, f"Key {key} cannot be empty."

        # Sanitize input (example: strip whitespace)
        data[key] = data[key].strip()

        # Add more specific validation rules here, e.g., regex for email, length checks, etc.
        # Example: Email validation using regex
        if key == 'username':
            email_regex = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
            if not re.match(email_regex, data[key]):
                return False, "Invalid email format."
            if len(data[key]) > 255:
                return False, "Username too long."

        if key == 'password':
            if len(data[key]) < 8:
                return False, "Password must be at least 8 characters long."
            if not re.search(r"[A-Z]", data[key]):
                return False, "Password must contain at least one uppercase letter."
            if not re.search(r"[a-z]", data[key]):
                return False, "Password must contain at least one lowercase letter."
            if not re.search(r"[0-9]", data[key]):
                return False, "Password must contain at least one number."
            if not re.search(r"[^a-zA-Z0-9]", data[key]):
                return False, "Password must contain at least one symbol."

    return True, None

# --- Password Hashing ---
def generate_salt():
    """Generates a random salt."""
    return secrets.token_hex(SALT_LENGTH // 2)  # Divide by 2 because token_hex returns 2 chars per byte

def hash_password(password, salt):
    """Hashes the password using SHA-256 with a salt."""
    salted_password = salt.encode('utf-8') + password.encode('utf-8')
    hashed_password = hashlib.sha256(salted_password).hexdigest()
    return hashed_password

def verify_password(stored_hash, stored_salt, password):
    """Verifies a password against a stored hash and salt."""
    hashed_password = hash_password(password, stored_salt)
    return hashed_password == stored_hash

# --- User Management Endpoints (Example) ---
@app.route('/register', methods=['GET', 'POST'])
@csrf.protect
@limiter.limit("5 per minute") # Rate limit registration attempts
def register_user():
    """Registers a new user."""
    if request.method == 'POST':
        data = request.form  # Use request.form for HTML forms
        is_valid, error_message = validate_input(data, ['username', 'password'])
        if not is_valid:
            return jsonify({'error': error_message}), 400

        username = data['username']
        password = data['password']

        salt = generate_salt()
        hashed_password = hash_password(password, salt)

        db = SessionLocal()
        try:
            # Use SQLAlchemy to execute the query (parameterized automatically)
            sql = text("INSERT INTO users (username, password_hash, salt) VALUES (:username, :password_hash, :salt)")
            db.execute(sql, {'username': username, 'password_hash': hashed_password, 'salt': salt})
            db.commit()

            return jsonify({'message': 'User registered successfully'}), 201

        except Exception as e:
            logging.error(f"Database error: {e}")
            db.rollback()
            return jsonify({'error': 'Registration failed'}), 500
        finally:
            db.close()

    return render_template('register.html', csrf_token=generate_csrf())

@app.route('/login', methods=['GET', 'POST'])
@csrf.protect
@limiter.limit("10 per minute") # Rate limit login attempts
def login_user():
    """Logs in an existing user."""
    if request.method == 'POST':
        data = request.form
        is_valid, error_message = validate_input(data, ['username', 'password'])
        if not is_valid:
            return jsonify({'error': error_message}), 400

        username = data['username']
        password = data['password']

        db = SessionLocal()
        try:
            sql = text("SELECT password_hash, salt FROM users WHERE username = :username")
            result = db.execute(sql, {'username': username}).fetchone()

            if result:
                stored_hash = result[0]
                stored_salt = result[1]

                if verify_password(stored_hash, stored_salt, password):
                    # Authentication successful
                    session_token = secrets.token_hex(32)
                    session['session_token'] = session_token
                    session['username'] = username  # Store username in session
                    session.permanent = True  # Make the session permanent
                    app.permanent_session_lifetime = SESSION_EXPIRY  # Set session expiry
                    return jsonify({'message': 'Login successful', 'token': session_token}), 200
                else:
                    return jsonify({'error': 'Invalid credentials'}), 401
            else:
                return jsonify({'error': 'Invalid credentials'}), 401

        except Exception as e:
            logging.error(f"Database error: {e}")
            return jsonify({'error': 'Login failed'}), 500
        finally:
            db.close()

    return render_template('login.html', csrf_token=generate_csrf())

@app.route('/logout', methods=['POST'])
@csrf.protect # Requires CSRF protection
def logout_user():
    """Logs out the current user."""
    session.pop('session_token', None)
    session.pop('username', None)
    return jsonify({'message': 'Logout successful'}), 200

# --- Example Data Retrieval Endpoint (with Parameterized Query) ---
@app.route('/data', methods=['GET'])
def get_data():
    """Retrieves data from the database based on a user-supplied ID."""
    user_id = request.args.get('id')

    if not user_id:
        return jsonify({'error': 'Missing ID parameter'}), 400

    # Input Validation:  Check if the ID is a valid integer
    try:
        user_id = int(user_id)
    except ValueError:
        return jsonify({'error': 'Invalid ID format. Must be an integer.'}), 400

    db = SessionLocal()
    try:
        # Parameterized Query:  Prevents SQL injection
        sql = text("SELECT * FROM data_table WHERE user_id = :user_id")
        result = db.execute(sql, {'user_id': user_id}).fetchall()

        # Convert results to a JSON-serializable format
        data = []
        for row in result:
            data.append({
                'id': row[0],  # Assuming 'id' is the first column
                'value': row[1], # Assuming 'value' is the second column
                # Add more columns as needed
            })

        return jsonify(data), 200

    except Exception as e:
        logging.error(f"Database error: {e}")
        return jsonify({'error': 'Failed to retrieve data'}), 500
    finally:
        db.close()

# --- Security Headers ---
@app.after_request
def add_security_headers(response):
    """Adds security headers to the HTTP response."""
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload'  # HSTS
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    # Example CSP - adjust to your needs!  This is very restrictive.
    # response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self';"
    return response

@app.errorhandler(400)
def bad_request(error):
    return jsonify({'error': 'Bad Request'}), 400

@app.errorhandler(500)
def internal_server_error(error):
    logging.exception("Internal Server Error")
    return jsonify({'error': 'Internal Server Error'}), 500

if __name__ == '__main__':
    app.run(debug=False, host="0.0.0.0")  # Disable debug mode in production

