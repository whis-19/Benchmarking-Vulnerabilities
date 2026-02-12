import re
import sqlite3
import os
import logging
from dotenv import load_dotenv
from email_validator import validate_email, EmailNotValidError
import bcrypt

# --- Configuration ---
load_dotenv()  # Load environment variables from .env
DATABASE_FILE = os.getenv("DATABASE_FILE", "users.db")  # Default to users.db if not set

# --- Logging Configuration ---
logging.basicConfig(filename='app.log', level=logging.ERROR, format='%(asctime)s - %(levelname)s - %(message)s')


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

def is_strong_password(password):
    """Checks if a password meets certain strength criteria."""
    if len(password) < 8:
        return False
    if not re.search(r"[a-z]", password):
        return False
    if not re.search(r"[A-Z]", password):
        return False
    if not re.search(r"[0-9]", password):
        return False
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):  # Common symbols
        return False
    return True


def create_database():
    """Creates the database and user table if they don't exist."""
    conn = None  # Initialize conn to None
    try:
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()

        # Create the users table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL
            )
        """)

        conn.commit()

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
    hashed_password = bcrypt.hashpw(password, bcrypt.gensalt())
    return hashed_password


def create_user(email, password):
    """Creates a new user in the database."""
    if not is_valid_email(email):
        raise ValueError("Invalid email address")

    if not is_strong_password(password):
        raise ValueError("Password must be at least 8 characters long and contain uppercase, lowercase, numbers, and symbols.")

    hashed_password = hash_password(password)

    conn = None
    try:
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()

        cursor.execute("INSERT INTO users (email, password_hash) VALUES (?, ?)",
                       (email, hashed_password))
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
    conn = None
    try:
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()

        cursor.execute("SELECT password_hash FROM users WHERE email = ?", (email,))
        result = cursor.fetchone()

        if result:
            stored_hash = result[0]
            password = password.encode('utf-8')
            return bcrypt.checkpw(password, stored_hash)
        else:
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

    conn = None
    try:
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()

        # Use parameterized query to prevent SQL injection
        cursor.execute("DELETE FROM users WHERE email = ?", (email,))
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
        if create_user("test@example.com", "SecurePassword123!"):
            print("User created successfully.")
        else:
            print("User creation failed.")
    except ValueError as e:
        print(e)

    # Example: Verify password
    if verify_password("test@example.com", "SecurePassword123!"):
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

