import secrets
import sqlite3
import bcrypt  # pip install bcrypt
import os
import re
import logging
import time

# --- Configuration ---
DATABASE_FILE = "users.db"
USERNAME_MIN_LENGTH = 3
USERNAME_MAX_LENGTH = 50
PASSWORD_MIN_LENGTH = 8
PASSWORD_MAX_LENGTH = 100
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_DURATION = 60  # seconds
LOG_FILE = "app.log"

# --- End Configuration ---

# --- Logging Configuration ---
logging.basicConfig(filename=LOG_FILE, level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')


def generate_salt() -> bytes:
    """Generates a cryptographically secure random salt for bcrypt."""
    return bcrypt.gensalt()


def hash_password(password: str, salt: bytes) -> str:
    """Hashes the password using bcrypt and the provided salt."""
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed_password.decode('utf-8')


def is_username_valid(username: str) -> bool:
    """Validates the username based on length and allowed characters."""
    if not (USERNAME_MIN_LENGTH <= len(username) <= USERNAME_MAX_LENGTH):
        return False
    # Allow alphanumeric characters and underscores
    if not re.match("^[a-zA-Z0-9_]+$", username):
        return False
    return True


def is_password_valid(password: str) -> bool:
    """Validates the password based on length and complexity."""
    if not (PASSWORD_MIN_LENGTH <= len(password) <= PASSWORD_MAX_LENGTH):
        return False
    # Require at least one uppercase letter, one lowercase letter, one digit, and one special character
    if not re.search("[A-Z]", password):
        return False
    if not re.search("[a-z]", password):
        return False
    if not re.search("[0-9]", password):
        return False
    if not re.search("[^a-zA-Z0-9]", password):
        return False
    return True


def create_user(username: str, password: str) -> bool:
    """Creates a new user in the database. Returns True on success, False on failure."""
    if not is_username_valid(username):
        logging.warning(f"Invalid username format: {username}")
        print("Invalid username format.  Must be alphanumeric and between {USERNAME_MIN_LENGTH} and {USERNAME_MAX_LENGTH} characters.")
        return False

    if not is_password_valid(password):
        logging.warning(f"Invalid password format for user: {username}")
        print(f"Invalid password format.  Must be between {PASSWORD_MIN_LENGTH} and {PASSWORD_MAX_LENGTH} characters and contain at least one uppercase letter, one lowercase letter, one digit, and one special character.")
        return False

    try:
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()

        # Check if the username already exists
        cursor.execute("SELECT COUNT(*) FROM users WHERE username = ?", (username,))
        if cursor.fetchone()[0] > 0:
            logging.warning(f"Attempt to create duplicate username: {username}")
            print(f"Username '{username}' already exists.")
            return False

        salt = generate_salt()
        hashed_password = hash_password(password, salt)

        cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password))
        conn.commit()
        logging.info(f"User '{username}' created successfully.")
        print(f"User '{username}' created successfully.")
        return True

    except sqlite3.Error as e:
        logging.error(f"Database error creating user {username}: {e}")
        print("An error occurred during user creation.  See logs for details.")
        return False
    finally:
        if conn:
            conn.close()


def verify_password(username: str, password: str) -> bool:
    """Verifies the password against the stored bcrypt hash."""
    try:
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()

        # Check if account is locked
        cursor.execute("SELECT locked_until FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()

        if result is None:
            logging.warning(f"User '{username}' not found during verification.")
            print("Invalid username or password.")  # Generic error message
            return False

        locked_until = result[0]
        if locked_until and locked_until > time.time():
            logging.warning(f"Account '{username}' is locked.")
            print("Account is locked. Please try again later.")
            return False

        cursor.execute("SELECT password FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()

        if result is None:
            logging.warning(f"User '{username}' not found during verification.")
            print("Invalid username or password.")  # Generic error message
            return False

        stored_hash = result[0]

        if bcrypt.checkpw(password.encode('utf-8'), stored_hash.encode('utf-8')):
            # Reset failed login attempts on successful login
            cursor.execute("UPDATE users SET failed_login_attempts = 0 WHERE username = ?", (username,))
            conn.commit()
            logging.info(f"Password verification successful for user: {username}")
            return True
        else:
            # Increment failed login attempts
            cursor.execute("UPDATE users SET failed_login_attempts = failed_login_attempts + 1 WHERE username = ?", (username,))
            conn.commit()
            logging.warning(f"Failed password attempt for user: {username}")
            check_and_lock_account(username, conn, cursor)  # Pass conn and cursor
            print("Invalid username or password.")  # Generic error message
            return False

    except sqlite3.Error as e:
        logging.error(f"Database error verifying password for user {username}: {e}")
        print("An error occurred during password verification.  See logs for details.") # Generic error message
        return False
    finally:
        if conn:
            conn.close()


def check_and_lock_account(username: str, conn, cursor):
    """Checks failed login attempts and locks the account if necessary."""
    cursor.execute("SELECT failed_login_attempts FROM users WHERE username = ?", (username,))
    result = cursor.fetchone()

    if result:
        failed_attempts = result[0]
        if failed_attempts >= MAX_LOGIN_ATTEMPTS:
            lock_account(username, conn, cursor)  # Pass conn and cursor


def lock_account(username: str, conn, cursor):
    """Locks the account for a specified duration."""
    locked_until = time.time() + LOCKOUT_DURATION
    cursor.execute("UPDATE users SET locked_until = ? WHERE username = ?", (locked_until, username))
    conn.commit()
    logging.warning(f"Account '{username}' locked due to excessive failed login attempts.")
    print("Account locked due to too many failed login attempts. Please try again later.")


def initialize_database():
    """Creates the users table if it doesn't exist."""
    conn = None
    try:
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                failed_login_attempts INTEGER DEFAULT 0,
                locked_until REAL
            )
        """)
        conn.commit()
        print("Database initialized successfully.")
        logging.info("Database initialized successfully.")
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        logging.error(f"Database error during initialization: {e}")
    finally:
        if conn:
            conn.close()


# --- Example Usage ---
if __name__ == "__main__":
    initialize_database()

    # Registration
    username = input("Enter username: ")
    password = input("Enter password: ")

    if create_user(username, password):
        print("Registration successful!")

        # Verification
        password_to_verify = input("Enter password to verify: ")
        if verify_password(username, password_to_verify):
            print("Password verification successful!")
        else:
            print("Password verification failed.")
    else:
        print("Registration failed.")

