import os
import sqlite3
from flask import Flask, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
import logging  # Import the logging module
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import re  # Import the regular expression module

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO,  # Or logging.ERROR for production
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Database Configuration (Important: Use environment variables for sensitive data)
DATABASE_PATH = os.environ.get("DATABASE_PATH")  # Remove the default value
if not DATABASE_PATH:
    logging.error("DATABASE_PATH environment variable not set!")
    raise ValueError("DATABASE_PATH environment variable not set!") # Or exit the program

SECRET_KEY = os.environ.get("SECRET_KEY")  # Remove the default value
if not SECRET_KEY:
    logging.error("SECRET_KEY environment variable not set!")
    raise ValueError("SECRET_KEY environment variable not set!") # Or exit the program

app.config['SECRET_KEY'] = SECRET_KEY

# Rate Limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]  # Adjust limits as needed
)


# --- Database Initialization (Run this once to create the database and table) ---
def initialize_database():
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            is_moderator INTEGER DEFAULT 0  -- 0 for False, 1 for True
        )
    """)
    conn.commit()
    conn.close()

# --- Example: Add an initial moderator (Run this once) ---
def create_initial_moderator(username, password):
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    hashed_password = generate_password_hash(password)
    try:
        cursor.execute("INSERT INTO users (username, password_hash, is_moderator) VALUES (?, ?, ?)",
                       (username, hashed_password, 1))
        conn.commit()
        logging.info(f"Moderator '{username}' created successfully.")
    except sqlite3.IntegrityError:
        logging.warning(f"User '{username}' already exists.")
    finally:
        conn.close()


# --- Route to check if a user is a moderator ---
@app.route("/is_moderator", methods=["POST"])
@limiter.limit("5/minute")  # Rate limit this endpoint
def is_moderator():
    """
    Checks if a user is a moderator based on username and password.

    Requires:
        - username (string): The username of the user.
        - password (string): The password of the user.

    Returns:
        - JSON: {"is_moderator": true/false} if the user exists and is a moderator.
                {"error": "Invalid credentials"} if the user does not exist or the password is incorrect.
                {"error": "Missing username or password"} if either is missing.
                {"error": "Authentication error"} if there's a database issue.
    """
    try:
        data = request.get_json()
        username = data.get("username")
        password = data.get("password")

        if not username or not password:
            return jsonify({"error": "Missing username or password"}), 400

        # Input Validation
        if not (3 <= len(username) <= 50):  # Example length limit
            return jsonify({"error": "Invalid username"}), 400

        # Password Complexity Check (Example)
        if not re.match(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+])[A-Za-z\d!@#$%^&*()_+]{8,100}$", password):
            return jsonify({"error": "Password does not meet complexity requirements"}), 400

        if not (8 <= len(password) <= 100): # Example length limit
            return jsonify({"error": "Invalid password"}), 400

        # The code continues to use parameterized queries, which is the primary defense
        # against SQL injection when using `sqlite3`. It's crucial to ensure that all
        # database interactions use this method.
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()

        cursor.execute("SELECT id, password_hash, is_moderator FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        conn.close()

        if user:
            user_id, password_hash, is_moderator = user
            if check_password_hash(password_hash, password):
                return jsonify({"is_moderator": bool(is_moderator)}), 200  # Convert to boolean
            else:
                logging.warning(f"Failed login attempt for user: {username}") # Log failed attempts
                return jsonify({"error": "Invalid credentials"}), 401
        else:
            logging.warning(f"User not found: {username}") # Log user not found
            return jsonify({"error": "Invalid credentials"}), 401

    except Exception as e:
        logging.exception("Database error during is_moderator check") # Log the full exception
        return jsonify({"error": "Authentication error"}), 500  # Generic error message


if __name__ == "__main__":
    # Initialize the database (if it doesn't exist)
    initialize_database()

    # Create an initial moderator (only run this once or when needed)
    # create_initial_moderator("admin", "secure_password")  # Replace with a real username and password

    # CORS and CSRF protection are not included in this example but should be
    # implemented in a production application using `flask-cors` and `Flask-WTF`
    # respectively.

    # Ensure the database file has appropriate file system permissions to prevent
    # unauthorized access.

    # While werkzeug.security is used for password hashing, bcrypt or argon2 are
    # recommended for stronger password hashing. Consider migrating to one of these
    # algorithms in the future.

    app.run(debug=False)  # Set debug=False in production!

