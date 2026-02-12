import sqlite3
import hashlib
import os
import configparser
import secrets  # Import the secrets module
import datetime
import logging
import bcrypt

# Configure logging
logging.basicConfig(filename='app.log', level=logging.ERROR, format='%(asctime)s - %(levelname)s - %(message)s')

# Configuration
config = configparser.ConfigParser()
config.read('config.ini')

DATABASE_PATH = config['database']['path']
SALT_LENGTH = 16
LOCKOUT_DURATION_MINUTES = 15
MAX_LOGIN_ATTEMPTS = 5

def create_database():
    """Creates the database and user table if they don't exist."""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            failed_login_attempts INTEGER DEFAULT 0,
            lockout_expiry DATETIME,
            password_reset_required BOOLEAN DEFAULT TRUE
        )
    """)
    conn.commit()
    conn.close()

def generate_salt(length=SALT_LENGTH):
    """Generates a random salt."""
    return os.urandom(length).hex()

def hash_password(password):
    """Hashes the password using bcrypt."""
    password = password.encode('utf-8')
    salt = bcrypt.gensalt()  # Generate a random salt
    hashed_password = bcrypt.hashpw(password, salt)
    return hashed_password.decode('utf-8')  # Store as string

def create_user(username, password):
    """Creates a new user account."""
    create_database()  # Ensure the database exists

    try:
        hashed_password = hash_password(password)

        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        cursor.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)",
                       (username, hashed_password))
        conn.commit()
        conn.close()
        return True  # User creation successful
    except sqlite3.IntegrityError:
        logging.error("Username already exists.")
        print("Username already exists.")
        return False # User creation failed (username exists)
    except Exception as e:
        logging.exception("Error creating user.")
        print(f"Error creating user.")
        return False # User creation failed (other error)

def verify_password(username, password):
    """Verifies the password against the stored hash."""
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()

        # Check for account lockout
        cursor.execute("SELECT lockout_expiry, password_reset_required, password_hash FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()

        if not result:
            conn.close()
            return False  # User not found

        lockout_expiry, password_reset_required, stored_password_hash = result

        if lockout_expiry:
            lockout_expiry_dt = datetime.datetime.fromisoformat(lockout_expiry)
            if datetime.datetime.now() < lockout_expiry_dt:
                print("Account is locked. Please try again later.")
                conn.close()
                return False

        if bcrypt.checkpw(password.encode('utf-8'), stored_password_hash.encode('utf-8')):
            # Reset failed login attempts and lockout expiry on successful login
            cursor.execute("UPDATE users SET failed_login_attempts = 0, lockout_expiry = NULL WHERE username = ?", (username,))
            conn.commit()
            conn.close()
            return True
        else:
            # Increment failed login attempts
            cursor.execute("UPDATE users SET failed_login_attempts = failed_login_attempts + 1 WHERE username = ?", (username,))
            conn.commit()

            # Check if account should be locked
            cursor.execute("SELECT failed_login_attempts FROM users WHERE username = ?", (username,))
            attempts = cursor.fetchone()[0]
            if attempts >= MAX_LOGIN_ATTEMPTS:
                lockout_time = datetime.datetime.now() + datetime.timedelta(minutes=LOCKOUT_DURATION_MINUTES)
                cursor.execute("UPDATE users SET lockout_expiry = ? WHERE username = ?", (lockout_time.isoformat(), username,))
                conn.commit()
                print("Account locked due to multiple failed login attempts.")

            conn.close()
            return False
    except Exception as e:
        logging.exception("Error verifying password.")
        print(f"Error verifying password.")
        return False

def first_login_mode(username):
    """Simulates a first login mode where the user must set a new password."""
    print("First login detected. Please set a new strong password.")
    new_password = input("Enter new password: ")
    if not new_password:
        print("Password cannot be empty.")
        return False

    hashed_password = hash_password(new_password)

    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET password_hash = ?, password_reset_required = FALSE WHERE username = ?",
                       (hashed_password, username))
        conn.commit()
        conn.close()
        print("Password updated successfully.")
        return True
    except Exception as e:
        logging.exception("Error updating password.")
        print(f"Error updating password.")
        return False

def check_password_reset_required(username):
    """Checks if the user needs to reset their password."""
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT password_reset_required FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()
        conn.close()
        if result:
            return result[0] == 1  # Assuming 1 represents True
        else:
            return False  # User not found
    except Exception as e:
        logging.exception("Error checking password reset requirement.")
        print(f"Error checking password reset requirement: {e}")
        return False

# Example Usage (Registration and Login)
if __name__ == "__main__":
    # Create a config.ini file (outside the source code directory)
    # with the following structure:
    # [database]
    # path = users.db
    #
    # IMPORTANT: Ensure that the config.ini file has restrictive permissions
    # (e.g., 600 or 400) so that only the user running the application can read it.
    # Consider using environment variables instead of a config file for better security.

    username = input("Enter username: ")
    password = input("Enter password: ")

    if create_user(username, password):
        print("User created successfully.")

        # Simulate login
        login_username = input("Enter username to login: ")
        login_password = input("Enter password to login: ")

        if verify_password(login_username, login_password):
            print("Login successful!")
            if check_password_reset_required(login_username):
                print("Password reset required.")
                first_login_mode(login_username)
        else:
            print("Login failed.")
    else:
        print("User creation failed.")

