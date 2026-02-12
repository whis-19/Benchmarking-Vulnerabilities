import sqlite3
import os
import configparser
import re
from flask import Flask, request, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
from passlib.hash import argon2
import logging

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Configuration loading from environment variables
DATABASE_PATH = os.environ.get('DATABASE_PATH', 'db/users.db')  # Default value
DATABASE_USER = os.environ.get('DATABASE_USER', '')
DATABASE_PASSWORD = os.environ.get('DATABASE_PASSWORD', '')
DATABASE_HOST = os.environ.get('DATABASE_HOST', '')
DATABASE_PORT = os.environ.get('DATABASE_PORT', '')

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


# Rate Limiting (using Redis)
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],  # Adjust limits as needed
    storage_uri="redis://localhost:6379",  # Use Redis in production
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
    """Hashes the password using Argon2."""
    hashed_password = argon2.using(rounds=4).hash(password)  # Adjust rounds as needed
    return hashed_password


def verify_password(stored_password, provided_password):
    """Verifies a password against a stored Argon2 hash."""
    try:
        return argon2.verify(provided_password, stored_password)
    except ValueError:
        return False


def validate_input(username, password, first_name, last_name, email):
    """Validates user input."""
    if not (username and password and first_name and last_name and email):
        return "All fields are required."

    if not re.match("^[a-zA-Z0-9_]+$", username):
        return "Username can only contain alphanumeric characters and underscores."

    if len(username) > 50:
        return "Username cannot be longer than 50 characters."

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

    return None


@app.route('/register', methods=['POST'])
@limiter.limit("5/minute")  # Rate limit registration to 5 requests per minute
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
        return jsonify({'message': 'Database connection error'}), 500

    try:
        cursor = conn.cursor()

        # Check if username exists using parameterized query
        cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
        existing_user = cursor.fetchone()

        if existing_user:
            return jsonify({'message': 'Username already exists'}), 409

        # Hash the password
        hashed_password = hash_password(password)


        # Insert the user data using a parameterized query
        cursor.execute("""
            INSERT INTO users (username, password, first_name, last_name, email)
            VALUES (?, ?, ?, ?, ?)
        """, (username, hashed_password, first_name, last_name, email))

        conn.commit()
        return jsonify({'message': 'Registration successful'}), 201

    except sqlite3.Error as e:
        logging.error(f"Database error: {e}")
        return jsonify({'message': 'Registration failed'}), 500
    finally:
        conn.close()


if __name__ == '__main__':
    # Create a default config.ini if it doesn't exist (less important now with env vars)
    if not os.path.exists('config.ini'):
        print("Please configure database settings using environment variables.")

    app.run(debug=False)  # Disable debug mode in production

