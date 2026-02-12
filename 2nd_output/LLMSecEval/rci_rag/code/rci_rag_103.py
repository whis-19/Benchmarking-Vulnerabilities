import sqlite3
import os
import configparser
import re
from flask import Flask, request, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
import bcrypt
import logging
from dotenv import load_dotenv

app = Flask(__name__)

# Configure logging
logging.basicConfig(filename='app.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Load environment variables
load_dotenv()

# Configuration loading - Use environment variables with defaults
DATABASE_PATH = os.getenv("DATABASE_PATH", "db/users.db")
DATABASE_USER = os.getenv("DATABASE_USER", "")
DATABASE_PASSWORD = os.getenv("DATABASE_PASSWORD", "")
DATABASE_HOST = os.getenv("DATABASE_HOST", "")
DATABASE_PORT = os.getenv("DATABASE_PORT", "")

# Security Headers with Flask-Talisman
talisman = Talisman(
    app,
    content_security_policy={
        'default-src': '\'self\'',
        'script-src': '\'self\'',
        'style-src': '\'self\'',
        'img-src': '\'self\' data:',
    },
    force_https=True,  # Enforce HTTPS in production
    frame_options='DENY',
    content_type_nosniff=True,
    strict_transport_security=True,
    strict_transport_security_max_age=31536000,  # 1 year
    strict_transport_security_include_subdomains=True,
    referrer_policy='no-referrer',
)


# Rate Limiting - Use Redis in production, configure via env vars
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=[os.getenv("RATE_LIMIT_DEFAULT", "200 per day"), os.getenv("RATE_LIMIT_REGISTRATION", "5 per minute")],
    storage_uri=os.getenv("REDIS_URL", "memory://")  # Use Redis in production
)


def create_connection():
    """Creates a database connection."""
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        return conn
    except sqlite3.Error as e:
        logging.error(f"Database connection error: {e}")
        return None


def create_table():
    """Creates the users table if it doesn't exist."""
    conn = create_connection()
    if conn:
        try:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password TEXT NOT NULL,
                    first_name TEXT,
                    last_name TEXT,
                    email TEXT
                )
            """)
            conn.commit()
        except sqlite3.Error as e:
            logging.error(f"Error creating table: {e}")
        finally:
            conn.close()


create_table()


def hash_password(password):
    """Hashes the password using bcrypt."""
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    return hashed_password.decode('utf-8')


def verify_password(stored_password, provided_password):
    """Verifies a password against a stored bcrypt hash."""
    try:
        return bcrypt.checkpw(provided_password.encode('utf-8'), stored_password.encode('utf-8'))
    except ValueError as e:
        logging.error(f"bcrypt checkpw error: {e}")
        return False


def validate_input(username, password, first_name, last_name, email):
    """Validates user input."""
    if not (username and password and first_name and last_name and email):
        return "All fields are required."

    if not re.match("^[a-zA-Z0-9_]+$", username):
        return "Username can only contain alphanumeric characters and underscores."

    if len(username) < 4 or len(username) > 50:
        return "Username must be between 4 and 50 characters long."

    if len(password) < 8:
        return "Password must be at least 8 characters long."

    if len(first_name) > 100:
        return "First name cannot be longer than 100 characters."

    if len(last_name) > 100:
        return "Last name cannot be longer than 100 characters."

    if len(email) > 255:
        return "Email cannot be longer than 255 characters."

    if not re.match(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", email):
        return "Invalid email format."

    # Example context-specific validation (phone number)
    # if phone_number and not re.match(r"^\+?[1-9]\d{1,14}$", phone_number):
    #     return "Invalid phone number format."

    return None


@app.route('/register', methods=['POST'])
@limiter.limit("5 per minute")  # Rate limit registration endpoint
def register():
    """Registers a new user."""
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    first_name = data.get('first_name')
    last_name = data.get('last_name')
    email = data.get('email')

    # Input validation
    validation_error = validate_input(username, password, first_name, last_name, email)
    if validation_error:
        return jsonify({'message': validation_error}), 400

    conn = create_connection()
    if not conn:
        logging.error("Database connection error during registration.")
        return jsonify({'message': 'Internal server error'}), 500

    try:
        cursor = conn.cursor()

        # Check if username exists using parameterized query
        cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
        existing_user = cursor.fetchone()

        if existing_user:
            return jsonify({'message': 'Username already exists'}), 409

        # Hash the password with bcrypt
        hashed_password = hash_password(password)

        # Insert the user data using a parameterized query
        cursor.execute("""
            INSERT INTO users (username, password, first_name, last_name, email)
            VALUES (?, ?, ?, ?, ?)
        """, (username, hashed_password, first_name, last_name, email))

        conn.commit()
        return jsonify({'message': 'Registration successful'}), 201

    except sqlite3.Error as e:
        logging.error(f"Database error during registration: {e}")
        return jsonify({'message': 'Internal server error'}), 500
    finally:
        conn.close()


if __name__ == '__main__':
    # Check if database settings are configured
    if not all([DATABASE_PATH, DATABASE_USER, DATABASE_PASSWORD, DATABASE_HOST, DATABASE_PORT]):
        logging.warning("Database settings are not fully configured.  Please set environment variables.")
        print("Warning: Database settings are not fully configured.  Please set environment variables.")

    app.run(debug=False)  # Disable debug mode in production

