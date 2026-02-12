import sqlite3
import secrets
import os
import bcrypt
import re
import logging
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from functools import wraps
from flask import Flask, request, abort

# --- Configuration ---
DATABASE_FILE = 'user_database.db'
PASSWORD_RESET_TOKEN_EXPIRY_SECONDS = 3600  # 1 hour
LOGIN_ATTEMPTS_WINDOW = 60  # seconds
MAX_LOGIN_ATTEMPTS = 5
ACCOUNT_LOCKOUT_DURATION = 300  # seconds

# --- Logging Setup ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- Flask App Setup (for rate limiting example) ---
app = Flask(__name__)
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]  # Example default rate limit
)

# --- Database Connection Pool (using a simple approach) ---
def get_db_connection():
    """Gets a database connection."""
    conn = sqlite3.connect(DATABASE_FILE)
    conn.row_factory = sqlite3.Row  # Access columns by name
    return conn

def close_db_connection(conn):
    """Closes a database connection."""
    if conn:
        conn.close()

# --- Custom Exceptions ---
class AuthenticationError(Exception):
    """Custom exception for authentication failures."""
    pass

class InputValidationError(Exception):
    """Custom exception for input validation errors."""
    pass

class DatabaseError(Exception):
    """Custom exception for database errors."""
    pass

# --- Helper Functions ---

def generate_salt():
    """Generates a cryptographically secure random salt (for legacy SHA-256)."""
    return secrets.token_hex(16)

def hash_password_bcrypt(password):
    """Hashes the password using bcrypt."""
    try:
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        return hashed_password.decode('utf-8')  # Store as string
    except Exception as e:
        logging.error(f"Error hashing password with bcrypt: {e}")
        raise DatabaseError("Failed to hash password.") from e

def verify_password_bcrypt(password, stored_hash):
    """Verifies a password against a bcrypt hash."""
    try:
        return bcrypt.checkpw(password.encode('utf-8'), stored_hash.encode('utf-8'))
    except Exception as e:
        logging.error(f"Error verifying password with bcrypt: {e}")
        return False  # Or raise an exception if appropriate

def create_table():
    """Creates the users table if it doesn't exist."""
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                -- No longer storing salt separately for bcrypt
                failed_login_attempts INTEGER DEFAULT 0,
                lockout_expiry DATETIME
            )
        """)
        conn.commit()
        logging.info("Users table created (if it didn't exist).")
    except sqlite3.Error as e:
        logging.error(f"Database error: {e}")
        raise DatabaseError("Failed to create users table.") from e
    finally:
        close_db_connection(conn)

# --- Rate Limiting Decorator (Example) ---
def rate_limit(limit):
    """Decorator for applying rate limiting."""
    def decorator(f):
        @wraps(f)
        @limiter.limit(limit)
        def wrapper(*args, **kwargs):
            return f(*args, **kwargs)
        return wrapper
    return decorator

# --- User Registration Function ---
def register_user(username, password):
    """Registers a new user in the database."""
    conn = None
    try:
        # Input validation
        if not (4 <= len(username) <= 50):
            raise InputValidationError("Username must be between 4 and 50 characters.")
        if not (8 <= len(password) <= 100):
            raise InputValidationError("Password must be between 8 and 100 characters.")
        if not re.match(r"^[a-zA-Z0-9_]+$", username):
            raise InputValidationError("Username must contain only alphanumeric characters and underscores.")

        # Hash the password using bcrypt
        password_hash = hash_password_bcrypt(password)

        # Connect to the database
        conn = get_db_connection()
        cursor = conn.cursor()

        # Insert the user data into the database
        cursor.execute("INSERT INTO users (username, password_hash, failed_login_attempts) VALUES (?, ?, 0)",
                       (username, password_hash))
        conn.commit()
        logging.info(f"User '{username}' registered successfully.")

    except sqlite3.IntegrityError:
        logging.warning(f"Username '{username}' already exists.")
        raise InputValidationError(f"Username '{username}' already exists.")
    except InputValidationError as e:
        logging.warning(f"Input error: {e}")
        raise
    except DatabaseError as e:
        logging.error(f"Database error: {e}")
        raise
    except Exception as e:
        logging.error(f"Unexpected error during registration: {e}")
        raise
    finally:
        close_db_connection(conn)

# --- Login Function ---
@limiter.limit(f"{MAX_LOGIN_ATTEMPTS} per {LOGIN_ATTEMPTS_WINDOW} seconds")
def login(username, password):
    """Logs in a user."""
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Check if account is locked
        cursor.execute("SELECT lockout_expiry FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()

        if result and result['lockout_expiry']:
            lockout_expiry = result['lockout_expiry']
            if lockout_expiry:
                # Convert lockout_expiry to a datetime object for comparison
                from datetime import datetime
                lockout_expiry_dt = datetime.fromisoformat(lockout_expiry)
                if datetime.now() < lockout_expiry_dt:
                    raise AuthenticationError("Account is locked. Please try again later.")

        cursor.execute("SELECT id, password_hash, failed_login_attempts FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()

        if not result:
            raise AuthenticationError("Invalid username or password.")

        user_id = result['id']
        stored_password_hash = result['password_hash']
        failed_attempts = result['failed_login_attempts']

        if verify_password_bcrypt(password, stored_password_hash):
            # Reset failed login attempts on successful login
            cursor.execute("UPDATE users SET failed_login_attempts = 0, lockout_expiry = NULL WHERE id = ?", (user_id,))
            conn.commit()
            logging.info(f"User '{username}' logged in successfully.")
            return True  # Or return user object, token, etc.
        else:
            # Increment failed login attempts
            new_failed_attempts = failed_attempts + 1
            cursor.execute("UPDATE users SET failed_login_attempts = ? WHERE id = ?", (new_failed_attempts, user_id))
            conn.commit()

            if new_failed_attempts >= MAX_LOGIN_ATTEMPTS:
                # Lock the account
                from datetime import datetime, timedelta
                lockout_expiry = datetime.now() + timedelta(seconds=ACCOUNT_LOCKOUT_DURATION)
                cursor.execute("UPDATE users SET lockout_expiry = ? WHERE id = ?", (lockout_expiry.isoformat(), user_id))
                conn.commit()
                logging.warning(f"Account '{username}' locked due to too many failed login attempts.")
                raise AuthenticationError("Account locked. Please try again later.")
            else:
                logging.warning(f"Failed login attempt for user '{username}'.")
                raise AuthenticationError("Invalid username or password.")

    except AuthenticationError as e:
        logging.warning(f"Authentication error: {e}")
        raise
    except Exception as e:
        logging.error(f"Unexpected error during login: {e}")
        raise
    finally:
        close_db_connection(conn)

# --- Password Reset Token Generation and Storage ---
def generate_password_reset_token(username):
    """Generates a password reset token and stores its hash in the database."""
    token = secrets.token_urlsafe(32)
    token_hash = hash_password_bcrypt(token)  # Hash the token using bcrypt

    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Store the token hash and expiry in the database
        from datetime import datetime, timedelta
        expiry_time = datetime.now() + timedelta(seconds=PASSWORD_RESET_TOKEN_EXPIRY_SECONDS)

        cursor.execute("UPDATE users SET reset_token_hash = ?, reset_token_expiry = ? WHERE username = ?",
                       (token_hash, expiry_time.isoformat(), username))  # Store expiry as ISO format
        conn.commit()
        return token  # Return the *unhashed* token to be sent to the user
    except Exception as e:
        logging.error(f"Error generating password reset token: {e}")
        raise
    finally:
        close_db_connection(conn)

def verify_password_reset_token(username, token):
    """Verifies a password reset token against the stored hash."""
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT reset_token_hash, reset_token_expiry FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()

        if not result:
            return False  # User not found

        stored_token_hash = result['reset_token_hash']
        expiry_time_str = result['reset_token_expiry']

        if not stored_token_hash or not expiry_time_str:
            return False  # No reset token found

        # Check if the token has expired
        from datetime import datetime
        expiry_time = datetime.fromisoformat(expiry_time_str)  # Parse ISO format
        if datetime.now() > expiry_time:
            return False  # Token expired

        # Verify the token
        return verify_password_bcrypt(token, stored_token_hash)

    except Exception as e:
        logging.error(f"Error verifying password reset token: {e}")
        return False
    finally:
        close_db_connection(conn)

def reset_password(username, new_password, token):
    """Resets the user's password after verifying the reset token."""
    conn = None
    try:
        if not verify_password_reset_token(username, token):
            raise AuthenticationError("Invalid or expired reset token.")

        # Hash the new password
        new_password_hash = hash_password_bcrypt(new_password)

        conn = get_db_connection()
        cursor = conn.cursor()

        # Update the password and clear the reset token
        cursor.execute("UPDATE users SET password_hash = ?, reset_token_hash = NULL, reset_token_expiry = NULL WHERE username = ?",
                       (new_password_hash, username))
        conn.commit()
        logging.info(f"Password reset successfully for user '{username}'.")

    except AuthenticationError as e:
        logging.warning(f"Authentication error during password reset: {e}")
        raise
    except Exception as e:
        logging.error(f"Error resetting password: {e}")
        raise
    finally:
        close_db_connection(conn)

# --- Example Usage (Replace SHA-256 calls) ---
# password_hash = hash_password_bcrypt(password)
# if verify_password_bcrypt(password, stored_password_hash):
#     # Password is correct

# --- Main Execution ---
if __name__ == "__main__":
    # Create the users table if it doesn't exist
    try:
        create_table()
    except DatabaseError as e:
        print(f"Failed to create table: {e}")
        exit(1)

    # Get user input (in a real application, use a proper UI)
    while True:
        print("\nChoose an action:")
        print("1. Register")
        print("2. Login")
        print("3. Exit")

        choice = input("Enter your choice: ")

        if choice == '1':
            try:
                username = input("Enter username: ")
                password = input("Enter password: ")
                register_user(username, password)
            except InputValidationError as e:
                print(f"Registration failed: {e}")
            except DatabaseError as e:
                print(f"Registration failed due to database error: {e}")
            except Exception as e:
                print(f"Registration failed due to an unexpected error: {e}")

        elif choice == '2':
            try:
                username = input("Enter username: ")
                password = input("Enter password: ")
                if login(username, password):
                    print("Login successful!")
                else:
                    print("Login failed.")
            except AuthenticationError as e:
                print(f"Login failed: {e}")
            except Exception as e:
                print(f"Login failed due to an unexpected error: {e}")

        elif choice == '3':
            break
        else:
            print("Invalid choice. Please try again.")

# --- Example Flask Routes (Illustrative) ---
@app.route('/register', methods=['POST'])
@rate_limit("5 per minute")  # Example rate limit
def register_route():
    try:
        username = request.form['username']
        password = request.form['password']
        register_user(username, password)
        return "Registration successful!", 201
    except InputValidationError as e:
        abort(400, str(e))  # Bad Request
    except DatabaseError as e:
        abort(500, "Internal Server Error")  # Internal Server Error
    except Exception as e:
        logging.exception("Unexpected error during registration")
        abort(500, "Internal Server Error")

@app.route('/login', methods=['POST'])
def login_route():
    try:
        username = request.form['username']
        password = request.form['password']
        if login(username, password):
            return "Login successful!", 200
        else:
            abort(401, "Invalid credentials")  # Unauthorized
    except AuthenticationError as e:
        abort(401, str(e))
    except Exception as e:
        logging.exception("Unexpected error during login")
        abort(500, "Internal Server Error")

# --- Security Headers (Example - configure in your web server for production) ---
@app.after_request
def add_security_headers(response):
    response.headers['Content-Security-Policy'] = "default-src 'self'"  # Example - customize!
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload'
    return response

# --- Error Handling (Example) ---
@app.errorhandler(400)
def bad_request(e):
    return f"Bad Request: {e.description}", 400

@app.errorhandler(401)
def unauthorized(e):
    return f"Unauthorized: {e.description}", 401

@app.errorhandler(500)
def internal_server_error(e):
    return "Internal Server Error", 500

# --- Run the Flask App (for demonstration) ---
if __name__ == '__main__':
    app.run(debug=True)  # Don't use debug mode in production!

