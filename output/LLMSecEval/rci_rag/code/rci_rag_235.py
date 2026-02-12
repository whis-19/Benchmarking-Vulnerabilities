import os
import hashlib
import secrets
import sqlite3
import configparser
import logging  # Import the logging module
import passlib.hash  # For bcrypt or Argon2
import re  # For regular expressions
import datetime  # For time-based account locking

# --- Configuration ---
config = configparser.ConfigParser()
config.read('/etc/myapp/config.ini')  # Secure location outside web root

DATABASE_PATH = config['database']['path']
ADMIN_USERNAME = config['admin']['username']
# ADMIN_PASSWORD = config['admin']['password']  # No longer directly used

# --- Logging Setup ---
logging.basicConfig(filename='/var/log/myapp.log', level=logging.ERROR,  # Secure log location
                    format='%(asctime)s - %(levelname)s - %(message)s')


# --- Helper Functions ---

def generate_salt():
    """Generates a random salt."""
    return secrets.token_hex(16)

def hash_password(password, salt):
    """Hashes the password using Argon2 (or bcrypt) with the given salt."""
    # Argon2 is generally preferred if available
    try:
        return passlib.hash.argon2.using(salt=salt).hash(password)
    except AttributeError:
        # Argon2 not available, fallback to bcrypt
        return passlib.hash.bcrypt.using(salt=salt).hash(password)


def create_database():
    """Creates the user database if it doesn't exist."""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            failed_login_attempts INTEGER DEFAULT 0,
            last_failed_login DATETIME,
            lockout_expiration DATETIME  -- Added for account locking
        )
    """)
    conn.commit()
    conn.close()

def create_admin_user():
    """Creates the initial admin user if it doesn't exist.  Generates a temporary password."""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    try:
        # Generate a temporary admin password
        temp_admin_password = secrets.token_urlsafe(32)  # Very strong temporary password
        salt = generate_salt()
        hashed_password = hash_password(temp_admin_password, salt)
        cursor.execute("INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)",
                       (ADMIN_USERNAME, hashed_password, salt))
        conn.commit()
        print(f"Admin user created with temporary password: {temp_admin_password}.  MUST BE CHANGED IMMEDIATELY!")
        logging.warning(f"Admin user created or reset for user {ADMIN_USERNAME}. Event ID: {secrets.token_hex(8)}") # Log this securely!
    except sqlite3.IntegrityError:
        print("Admin user already exists.")
    finally:
        conn.close()


# --- User Management Functions ---

def register_user(username, password):
    """Registers a new user."""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()

    # Stronger Password Complexity Validation (using regex)
    if len(password) < 12:
        print("Password must be at least 12 characters long.")
        return False

    if not re.search(r"[A-Z]", password):
        print("Password must contain at least one uppercase letter.")
        return False

    if not re.search(r"[a-z]", password):
        print("Password must contain at least one lowercase letter.")
        return False

    if not re.search(r"[0-9]", password):
        print("Password must contain at least one digit.")
        return False

    if not re.search(r"[!@#$%^&*()]", password):
        print("Password must contain at least one special character.")
        return False

    # Add more complex checks here (e.g., password blacklist, entropy)

    salt = generate_salt()
    hashed_password = hash_password(password, salt)

    try:
        cursor.execute("INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)",
                       (username, hashed_password, salt))
        conn.commit()
        print(f"User {username} registered successfully.")
        return True
    except sqlite3.IntegrityError:
        print(f"Username {username} already exists.")
        return False
    finally:
        conn.close()


def verify_password(username, password):
    """Verifies the password for a given user."""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()

    cursor.execute("SELECT password_hash, salt, failed_login_attempts, lockout_expiration FROM users WHERE username = ?", (username,))
    result = cursor.fetchone()

    if result:
        stored_hash, salt, failed_attempts, lockout_expiration = result

        now = datetime.datetime.now()

        # Account Locking with Time-Based Lockout
        if lockout_expiration and datetime.datetime.fromisoformat(lockout_expiration) > now:
            print("Account locked. Please try again later.")
            return False

        hashed_password = hash_password(password, salt)
        if hashed_password == stored_hash:
            # Reset failed attempts and lockout on successful login
            cursor.execute("UPDATE users SET failed_login_attempts = 0, lockout_expiration = NULL WHERE username = ?", (username,))
            conn.commit()
            return True
        else:
            # Increment failed attempts and lock account if necessary
            new_failed_attempts = failed_attempts + 1
            lockout_time = None
            if new_failed_attempts >= 5:
                lockout_duration = datetime.timedelta(minutes=5)  # Lock for 5 minutes
                lockout_time = now + lockout_duration
                lockout_time_str = lockout_time.isoformat()
                print(f"Account locked until {lockout_time_str}")
                cursor.execute("UPDATE users SET lockout_expiration = ? WHERE username = ?", (lockout_time_str, username,))
                logging.warning(f"Account locked for user {username} until {lockout_time_str}") # Log lockout event
            else:
                logging.warning(f"Failed login attempt for user {username} from unknown source.") # Log failed attempt

            cursor.execute("UPDATE users SET failed_login_attempts = ? WHERE username = ?", (new_failed_attempts, username,))
            conn.commit()
            print("Login failed.")
            return False
    else:
        print(f"User {username} not found.")
        return False
    finally:
        conn.close()


# --- Main Execution ---

if __name__ == "__main__":
    # Initialize the database and admin user
    create_database()
    create_admin_user()

    # Example Usage (replace with your actual form handling)
    new_username = input("Enter a username to register: ")
    new_password = input("Enter a password: ")

    if register_user(new_username, new_password):
        print("Registration successful!")

        login_username = input("Enter your username to login: ")
        login_password = input("Enter your password: ")

        if verify_password(login_username, login_password):
            print("Login successful!")
        else:
            print("Login failed.")
    else:
        print("Registration failed.")

