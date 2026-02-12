import bcrypt
import sqlite3
import re  # For input validation
import time  # For rate limiting
import logging  # For secure logging
import os  # For checking database file permissions

# --- Configuration ---
DATABASE_PATH = "users.db"
MAX_USERNAME_LENGTH = 50
MAX_PASSWORD_LENGTH = 100
RATE_LIMIT_WINDOW = 60  # seconds
MAX_ATTEMPTS = 5

# --- Logging Configuration ---
logging.basicConfig(filename='app.log', level=logging.ERROR, format='%(asctime)s - %(levelname)s - %(message)s')


# --- Helper Functions ---

def hash_password(password):
    """Hashes the password using bcrypt."""
    password_bytes = password.encode('utf-8')
    hashed_password = bcrypt.hashpw(password_bytes, bcrypt.gensalt())
    return hashed_password  # Return as bytes

def validate_input(username, password):
    """Validates username and password."""
    if not (1 <= len(username) <= MAX_USERNAME_LENGTH and 1 <= len(password) <= MAX_PASSWORD_LENGTH):
        return False, f"Username and password must be between 1 and {max(MAX_USERNAME_LENGTH, MAX_PASSWORD_LENGTH)} characters."

    if not re.match("^[a-zA-Z0-9_]+$", username):  # Alphanumeric and underscore only
        return False, "Username must contain only alphanumeric characters and underscores."

    # Password complexity checks
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter."
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter."
    if not re.search(r"[0-9]", password):
        return False, "Password must contain at least one number."
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False, "Password must contain at least one special character."

    return True, None

def get_user_attempts(username, db_path=DATABASE_PATH):
    """Retrieves the number of failed login attempts for a user."""
    conn = None
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT attempts, last_attempt FROM attempts WHERE username = ?", (username,))
        result = cursor.fetchone()
        if result:
            attempts, last_attempt = result
            return attempts, last_attempt
        else:
            return 0, 0  # User not found, no attempts yet
    except sqlite3.Error as e:
        logging.error(f"Database error: {e}")
        return MAX_ATTEMPTS, 0 # Prevent login if there's a database error
    finally:
        if conn:
            conn.close()

def update_user_attempts(username, attempts, db_path=DATABASE_PATH):
    """Updates the number of failed login attempts for a user."""
    conn = None
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        if attempts == 0:
            cursor.execute("DELETE FROM attempts WHERE username = ?", (username,))
        else:
            cursor.execute("""
                INSERT OR REPLACE INTO attempts (username, attempts, last_attempt)
                VALUES (?, ?, ?)
            """, (username, attempts, int(time.time())))
        conn.commit()
    except sqlite3.Error as e:
        logging.error(f"Database error: {e}")
    finally:
        if conn:
            conn.close()

def check_database_permissions(db_path):
    """Checks if the database file has appropriate permissions."""
    try:
        # Check if the file exists and is writable
        if os.path.exists(db_path):
            if not os.access(db_path, os.W_OK):
                logging.error(f"Database file '{db_path}' is not writable.  Please check file permissions.")
                return False
        else:
            # If the file doesn't exist, check if the directory is writable
            db_dir = os.path.dirname(db_path)
            if not db_dir:
                db_dir = "."  # Current directory
            if not os.access(db_dir, os.W_OK):
                logging.error(f"Database directory '{db_dir}' is not writable. Please check directory permissions.")
                return False
        return True
    except Exception as e:
        logging.error(f"Error checking database permissions: {e}")
        return False


# --- Core Functions ---

def create_user(username, password, db_path=DATABASE_PATH):
    """Creates a new user in the database with a hashed password."""

    # 1. Input Validation
    is_valid, error_message = validate_input(username, password)
    if not is_valid:
        print(f"Input error: {error_message}")
        return False

    # 2. Hash the password using bcrypt
    hashed_password = hash_password(password)

    # 3. Connect to the database
    conn = None
    try:
        if not check_database_permissions(db_path):
            return False

        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # 4. Create the users table if it doesn't exist
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                hashed_password BLOB NOT NULL
            )
        """)

        # Create the attempts table if it doesn't exist
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS attempts (
                username TEXT PRIMARY KEY,
                attempts INTEGER NOT NULL,
                last_attempt INTEGER NOT NULL
            )
        """)

        # 5. Insert the username and hashed password into the database
        try:
            cursor.execute("INSERT INTO users (username, hashed_password) VALUES (?, ?)",
                           (username, sqlite3.Binary(hashed_password)))
            conn.commit()
            print(f"User '{username}' created successfully.")
            return True
        except sqlite3.IntegrityError:
            print(f"Username '{username}' already exists.")
            return False

    except sqlite3.Error as e:
        logging.error(f"Database error: {e}")
        return False
    finally:
        if conn:
            conn.close()

def verify_password(username, password, db_path=DATABASE_PATH):
    """Verifies the password against the stored hash."""

    # 1. Rate Limiting
    attempts, last_attempt = get_user_attempts(username, db_path)
    if attempts >= MAX_ATTEMPTS:
        time_since_last_attempt = int(time.time()) - last_attempt
        if time_since_last_attempt < RATE_LIMIT_WINDOW:
            print(f"Too many failed attempts. Please wait {RATE_LIMIT_WINDOW - time_since_last_attempt} seconds before trying again.")
            return False
        else:
            # Reset attempts if the rate limit window has passed
            update_user_attempts(username, 0, db_path)
            attempts = 0

    conn = None
    try:
        if not check_database_permissions(db_path):
            return False

        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        cursor.execute("SELECT hashed_password FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()

        if result:
            hashed_password = result[0]  # Retrieve as bytes (BLOB)
            password_bytes = password.encode('utf-8')

            if bcrypt.checkpw(password_bytes, hashed_password):
                # Reset attempts on successful login
                update_user_attempts(username, 0, db_path)
                print("Password verified successfully.")
                return True
            else:
                # Increment attempts on failed login
                update_user_attempts(username, attempts + 1, db_path)
                print("Incorrect password.")
                return False
        else:
            print("User not found.")
            return False

    except sqlite3.Error as e:
        logging.error(f"Database error: {e}")
        return False
    finally:
        if conn:
            conn.close()

# --- Example Usage ---

if __name__ == "__main__":
    # Example usage:
    while True:
        action = input("Create user (c) or Verify password (v) or Exit (e)? ").lower()

        if action == 'c':
            username = input("Enter username: ")
            password = input("Enter password: ")
            create_user(username, password)
        elif action == 'v':
            username = input("Enter username: ")
            password = input("Enter password: ")
            verify_password(username, password)
        elif action == 'e':
            break
        else:
            print("Invalid action.")

