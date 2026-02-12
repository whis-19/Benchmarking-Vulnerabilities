import sqlite3
import bcrypt
import os
import re
import logging

# Configure logging
logging.basicConfig(filename='registration.log', level=logging.ERROR,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Database configuration
DATABASE_FILE = "user_database.db"

# --- Helper Functions ---

def hash_password(password):
    """Hashes the password using bcrypt."""
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    return hashed_password.decode('utf-8')  # Store as string


def create_table():
    """Creates the users table if it doesn't exist."""
    try:
        with sqlite3.connect(DATABASE_FILE) as conn:  # Use context manager
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL
                )
            """)
            conn.commit()
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        logging.error(f"Database error during table creation: {e}")


def insert_user(username, password_hash):
    """Inserts a new user into the database after hashing the password."""

    try:
        with sqlite3.connect(DATABASE_FILE) as conn:  # Use context manager
            cursor = conn.cursor()
            cursor.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)",
                           (username, password_hash))  # Parameterized query
            conn.commit()
            print(f"User '{username}' successfully registered.")
    except sqlite3.IntegrityError:
        print(f"Username '{username}' already exists. Please choose a different username.")
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        logging.error(f"Database error during user insertion: {e}")  # Log the error


def is_valid_username(username):
    """Checks if the username is valid."""
    if not re.match(r"^[a-zA-Z0-9_.-]{3,32}$", username):  # Allow periods and hyphens, limit length
        return False
    return True


def is_strong_password(password):
    """Checks if the password meets complexity requirements."""
    if len(password) < 8:
        return False
    if not re.search(r"[a-z]", password):
        return False
    if not re.search(r"[A-Z]", password):
        return False
    if not re.search(r"[0-9]", password):
        return False
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False
    return True


# --- Main Function ---

def register_user():
    """Prompts the user for username and password, then registers the user."""
    while True:
        username = input("Enter a username: ").strip()
        if not username:
            print("Username cannot be empty.")
            continue
        if not is_valid_username(username):
            print("Invalid username.  Only alphanumeric characters, underscores, periods, and hyphens are allowed (3-32 characters).")
            continue
        break

    while True:
        password = input("Enter a password: ").strip()
        if not password:
            print("Password cannot be empty.")
            continue
        if not is_strong_password(password):
            print("Password must be at least 8 characters long and contain at least one uppercase letter, one lowercase letter, one digit, and one special character.")
            continue
        break

    password_hash = hash_password(password)
    insert_user(username, password_hash)


# --- Execution ---

if __name__ == "__main__":
    # Ensure the database file has appropriate permissions (important for security)
    # This is especially important on shared systems.
    if not os.path.exists(DATABASE_FILE):
        create_table()  # Create the table if the database doesn't exist
        try:
            os.chmod(DATABASE_FILE, 0o600)  # Read/write for owner only
        except OSError as e:
            print(f"Warning: Could not set file permissions on database: {e}")
            print("Consider setting permissions manually for enhanced security.")
            logging.warning(f"Could not set file permissions on database: {e}") # Log the warning
    else:
        try:
            # Check if permissions are too open.  This is a warning, not a fatal error.
            file_permissions = os.stat(DATABASE_FILE).st_mode & 0o777
            if file_permissions & 0o007: # World or group writable
                print(f"Warning: Database file permissions are too open (0o{file_permissions:o}).  Consider restricting permissions to 0o600 for enhanced security.")
                logging.warning(f"Database file permissions are too open (0o{file_permissions:o}).") # Log the warning
        except OSError as e:
            print(f"Warning: Could not check file permissions on database: {e}")
            logging.warning(f"Could not check file permissions on database: {e}") # Log the warning

    register_user()

