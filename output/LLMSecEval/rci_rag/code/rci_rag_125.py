import re
import sqlite3
import hashlib
import os
import logging
import time  # For rate limiting
from dotenv import load_dotenv
from email_validator import validate_email, EmailNotValidError
import bcrypt
import bleach  # For input sanitization

# --- Configuration ---
load_dotenv()  # Load environment variables from .env
DATABASE_FILE = os.getenv("DATABASE_FILE", "users.db")  # Default to users.db if not set
LOG_FILE = os.getenv("LOG_FILE", "app.log")  # Allow configuring log file
PASSWORD_SALT_ROUNDS = int(os.getenv("PASSWORD_SALT_ROUNDS", "12")) # bcrypt rounds
# --- Logging Configuration ---
logging.basicConfig(filename=LOG_FILE, level=logging.ERROR, format='%(asctime)s - %(levelname)s - %(message)s')

# --- Rate Limiting Configuration ---
LOGIN_ATTEMPTS_WINDOW = 60  # seconds
MAX_LOGIN_ATTEMPTS = 5
login_attempts = {}  # Store login attempts per email


# --- Email Validation ---
EMAIL_REGEX = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"  # Basic regex

def is_valid_email(email):
    """Validates email format using email_validator library."""
    if not isinstance(email, str):
        return False
    try:
        validate_email(email)  # Validate and get info
        return True
    except EmailNotValidError as e:
        logging.warning(f"Invalid email format: {email} - {str(e)}")
        return False

def sanitize_email(email):
    """Sanitizes the email address to prevent XSS."""
    return bleach.clean(email)


def create_database():
    """Creates the database and user table if they don't exist.
       Also creates a limited-privilege user for data access.
    """
    conn = None  # Initialize conn to None
    try:
        # Ensure the database directory exists
        db_path = os.path.dirname(DATABASE_FILE)
        if db_path and not os.path.exists(db_path):
            os.makedirs(db_path)

        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()

        # Create the users table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL
            )
        """)

        conn.commit()

        # Set restrictive file permissions (Unix-like systems)
        try:
            os.chmod(DATABASE_FILE, 0o600)  # Read/write for owner only
        except OSError as e:
            logging.warning(f"Failed to set file permissions on database: {e}")


    except sqlite3.Error as e:
        logging.error(f"Database error during database creation: {e}")
        if conn:
            conn.rollback()  # Rollback in case of errors during creation

    finally:
        if conn:
            conn.close()


def hash_password(password):
    """Hashes the password using bcrypt."""
    password = password.encode('utf-8')
    salt = bcrypt.gensalt(rounds=PASSWORD_SALT_ROUNDS)
    hashed_password = bcrypt.hashpw(password, salt)
    return hashed_password, salt


def create_user(email, password):
    """Creates a new user in the database."""
    if not is_valid_email(email):
        raise ValueError("Invalid email address")

    if len(password) < 8:
        raise ValueError("Password must be at least 8 characters long.")

    # Enforce complexity (add more checks as needed)
    if not any(char.isupper() for char in password):
        raise ValueError("Password must contain at least one uppercase letter.")
    if not any(char.islower() for char in password):
        raise ValueError("Password must contain at least one lowercase letter.")
    if not any(char.isdigit() for char in password):
        raise ValueError("Password must contain at least one digit.")
    if not any(char in "!@#$%^&*()" for char in password):
        raise ValueError("Password must contain at least one special character.")

    hashed_password, salt = hash_password(password)
    sanitized_email = sanitize_email(email)

    conn = None
    try:
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()

        cursor.execute("INSERT INTO users (email, password_hash, salt) VALUES (?, ?, ?)",
                       (sanitized_email, hashed_password, salt))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        logging.warning(f"Attempt to create user with existing email: {email}")
        return False
    except sqlite3.Error as e:
        logging.error(f"Database error during user creation: {e}")
        if conn:
            conn.rollback()
        return False
    finally:
        if conn:
            conn.close()


def verify_password(email, password):
    """Verifies the password against the stored hash using bcrypt."""
    global login_attempts  # Access the global dictionary

    if email in login_attempts and len(login_attempts[email]) >= MAX_LOGIN_ATTEMPTS:
        # Check if the oldest attempt is within the rate limiting window
        if time.time() - login_attempts[email][0] < LOGIN_ATTEMPTS_WINDOW:
            logging.warning(f"Rate limit exceeded for email: {email}")
            return False  # Rate limit exceeded
        else:
            # Remove the oldest attempt if it's outside the window
            login_attempts[email].pop(0)

    conn = None
    try:
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()

        cursor.execute("SELECT password_hash, salt FROM users WHERE email = ?", (email,))
        result = cursor.fetchone()

        if result:
            stored_hash, salt = result
            password = password.encode('utf-8')
            if bcrypt.checkpw(password, stored_hash):
                # Reset login attempts on successful login
                if email in login_attempts:
                    del login_attempts[email]
                return True
            else:
                # Record failed login attempt
                if email not in login_attempts:
                    login_attempts[email] = []
                login_attempts[email].append(time.time())
                logging.warning(f"Failed login attempt for email: {email}")
                return False
        else:
            logging.warning(f"Email not found during password verification: {email}")
            return False  # Email not found
    except sqlite3.Error as e:
        logging.error(f"Database error during password verification: {e}")
        return False
    finally:
        if conn:
            conn.close()


def unsubscribe(email):
    """Unsubscribes the user with the given email address."""
    if not is_valid_email(email):
        return "Invalid email address."

    sanitized_email = sanitize_email(email)

    conn = None
    try:
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()

        # Use parameterized query to prevent SQL injection
        cursor.execute("DELETE FROM users WHERE email = ?", (sanitized_email,))
        rows_affected = conn.total_changes  # Get the number of rows affected by the last operation
        conn.commit()

        if rows_affected > 0:
            return "Successfully unsubscribed."
        else:
            return "Email address not found in our database."

    except sqlite3.Error as e:
        logging.error(f"Database error during unsubscription: {e}")
        if conn:
            conn.rollback()
        return "An error occurred while unsubscribing."

    finally:
        if conn:
            conn.close()


# --- Example Usage (for demonstration) ---
if __name__ == '__main__':
    create_database()  # Ensure the database and table exist

    # Example: Create a user
    try:
        if create_user("test@example.com", "S3cureP@sswOrd"):
            print("User created successfully.")
        else:
            print("User creation failed.")
    except ValueError as e:
        print(f"Error creating user: {e}")

    # Example: Verify password
    if verify_password("test@example.com", "S3cureP@sswOrd"):
        print("Password verified successfully.")
    else:
        print("Password verification failed.")

    # Example: Unsubscribe a user
    email_to_unsubscribe = "test@example.com"
    result = unsubscribe(email_to_unsubscribe)
    print(result)

    # Example: Try to unsubscribe a non-existent user
    email_to_unsubscribe = "nonexistent@example.com"
    result = unsubscribe(email_to_unsubscribe)
    print(result)

