import bcrypt
import os
import secrets
import sqlite3
import re
import logging

# --- Configuration ---
DATABASE_FILE = "users.db"  # Database file path
USERNAME_MIN_LENGTH = 3
USERNAME_MAX_LENGTH = 50
PASSWORD_MIN_LENGTH = 8
PASSWORD_MAX_LENGTH = 100
MAX_LOGIN_ATTEMPTS = 5
# --- End Configuration ---

# Configure logging
logging.basicConfig(filename='app.log', level=logging.ERROR, format='%(asctime)s - %(levelname)s - %(message)s')


def hash_password(password: str) -> bytes:
    """Hashes the password using bcrypt."""
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    return hashed_password


def sanitize_username(username: str) -> str:
    """Sanitizes the username to prevent SQL injection."""
    # Allow only alphanumeric characters and underscores
    sanitized_username = re.sub(r'[^a-zA-Z0-9_]', '', username)
    return sanitized_username


def validate_username(username: str) -> bool:
    """Validates the username."""
    if not (USERNAME_MIN_LENGTH <= len(username) <= USERNAME_MAX_LENGTH):
        print(f"Invalid username length. Must be between {USERNAME_MIN_LENGTH} and {USERNAME_MAX_LENGTH} characters.")
        return False
    if not re.match(r"^[a-zA-Z0-9_]+$", username):  # Alphanumeric and underscore only
        print("Invalid username characters. Only alphanumeric characters and underscores are allowed.")
        return False
    return True


def validate_password(password: str) -> bool:
    """Validates the password."""
    if not (PASSWORD_MIN_LENGTH <= len(password) <= PASSWORD_MAX_LENGTH):
        print(f"Invalid password length. Must be between {PASSWORD_MIN_LENGTH} and {PASSWORD_MAX_LENGTH} characters.")
        return False
    # Add more complexity checks here (e.g., require special characters, numbers)
    if not re.search(r"[a-z]", password):
        print("Password must contain at least one lowercase letter.")
        return False
    if not re.search(r"[A-Z]", password):
        print("Password must contain at least one uppercase letter.")
        return False
    if not re.search(r"[0-9]", password):
        print("Password must contain at least one digit.")
        return False
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        print("Password must contain at least one special character.")
        return False
    return True


def create_user(username: str, password: str) -> bool:
    """Creates a new user in the database.  Returns True on success, False on failure (e.g., username already exists)."""
    username = sanitize_username(username)

    if not validate_username(username):
        return False
    if not validate_password(password):
        return False

    try:
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()

        # Check if the username already exists
        cursor.execute("SELECT username FROM users WHERE username = ?", (username,))
        if cursor.fetchone():
            print(f"Error: Username '{username}' already exists.")
            return False

        hashed_password = hash_password(password)
        password = ""  # Clear password from memory

        cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password))
        conn.commit()
        print(f"User '{username}' created successfully.")
        return True

    except sqlite3.Error as e:
        logging.exception("Database error during user creation:")
        print("An error occurred during user creation. Please try again later.")
        return False
    finally:
        if conn:
            conn.close()


def verify_password(username: str, password: str) -> bool:
    """Verifies the password against the stored bcrypt hash."""
    username = sanitize_username(username)

    try:
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()

        cursor.execute("SELECT password, failed_attempts, locked FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()

        if not result:
            print(f"User '{username}' not found.")
            return False

        stored_hash, failed_attempts, locked = result
        if locked:
            print("Account is locked. Please contact support.")
            return False

        if bcrypt.checkpw(password.encode('utf-8'), stored_hash):
            # Reset failed attempts on successful login
            cursor.execute("UPDATE users SET failed_attempts = 0 WHERE username = ?", (username,))
            conn.commit()
            return True
        else:
            # Increment failed attempts
            failed_attempts += 1
            if failed_attempts >= MAX_LOGIN_ATTEMPTS:
                cursor.execute("UPDATE users SET failed_attempts = ?, locked = 1 WHERE username = ?", (failed_attempts, username))
                print("Account locked due to too many failed login attempts.")
            else:
                cursor.execute("UPDATE users SET failed_attempts = ? WHERE username = ?", (failed_attempts, username))
                print("Incorrect password.")

            conn.commit()
            return False

    except sqlite3.Error as e:
        logging.exception("Database error during password verification:")
        print("An error occurred during password verification. Please try again later.")
        return False
    finally:
        if conn:
            conn.close()


def initialize_database():
    """Creates the users table if it doesn't exist."""
    conn = None  # Initialize conn to None
    try:
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password BLOB NOT NULL,
                failed_attempts INTEGER NOT NULL DEFAULT 0,
                locked INTEGER NOT NULL DEFAULT 0
            )
        """)
        conn.commit()
        print("Database initialized.")
    except sqlite3.Error as e:
        logging.exception("Database error during database initialization:")
        print("An error occurred during database initialization. Please try again later.")
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

