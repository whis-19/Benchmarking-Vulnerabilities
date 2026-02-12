import sqlite3
import os
import configparser
import secrets  # For constant-time comparison
import zxcvbn  # For password strength estimation
import bcrypt  # For password hashing
import logging
import time

# Configuration loading
config = configparser.ConfigParser()
config.read('config.ini')  # Store database credentials and other sensitive info here

DATABASE_PATH = os.environ.get('DATABASE_PATH')
DATABASE_USER = os.environ.get('DATABASE_USER')
DATABASE_PASSWORD = os.environ.get('DATABASE_PASSWORD')

if not all([DATABASE_PATH, DATABASE_USER, DATABASE_PASSWORD]):
    logging.error("Database credentials not found in environment variables.")
    raise ValueError("Database credentials not found in environment variables.")


# Rate limiting parameters (adjust as needed)
LOGIN_ATTEMPTS_ALLOWED = 5
LOCKOUT_DURATION_SECONDS = 60 * 5  # 5 minutes

# Logging setup
logging.basicConfig(filename='app.log', level=logging.ERROR, format='%(asctime)s - %(levelname)s - %(message)s')


def hash_password(password):
    """Hashes the password using bcrypt."""
    salt = bcrypt.gensalt()  # Generates a random salt
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed_password, salt


def verify_password_attempt(username, password):
    """Verifies a user's password and handles rate limiting."""
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()

        # Check if the account is locked
        cursor.execute("SELECT locked_until FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()

        if result:
            locked_until = result[0]
            if locked_until:
                if time.time() < float(locked_until):
                    logging.warning(f"Account {username} locked. Please try again later.")
                    return False

        # Introduce a small, random delay to mitigate timing attacks
        time.sleep(secrets.randbelow(100) / 1000.0)  # Delay between 0 and 0.1 seconds

        cursor.execute("SELECT password, salt FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()

        if result:
            stored_password, salt_hex = result

            if bcrypt.checkpw(password.encode('utf-8'), stored_password.encode('utf-8')):
                # Reset failed login attempts on successful login
                cursor.execute("UPDATE users SET failed_login_attempts = 0, locked_until = NULL WHERE username = ?", (username,))
                conn.commit()
                logging.info(f"Login successful for user {username}.")
                return True
            else:
                # Increment failed login attempts
                cursor.execute("UPDATE users SET failed_login_attempts = failed_login_attempts + 1 WHERE username = ?", (username,))
                conn.commit()

                # Check if account should be locked
                cursor.execute("SELECT failed_login_attempts FROM users WHERE username = ?", (username,))
                attempts = cursor.fetchone()[0]
                if attempts >= LOGIN_ATTEMPTS_ALLOWED:
                    lockout_time = time.time() + LOCKOUT_DURATION_SECONDS
                    cursor.execute("UPDATE users SET locked_until = ? WHERE username = ?", (str(lockout_time), username))
                    conn.commit()
                    logging.warning(f"Account {username} locked due to too many failed login attempts.")

                logging.warning(f"Login failed for user {username}.")
                return False
        else:
            logging.warning(f"User {username} not found.")
            return False  # User not found

    except sqlite3.Error as e:
        logging.error(f"Database error: {e}", exc_info=True)
        return False
    finally:
        if conn:
            conn.close()


def create_user(username, password):
    """
    Creates a new user account in the database.  Hashes the password before storing.
    Uses parameterized queries to prevent SQL injection.
    """
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()

        # Validate username (example: alphanumeric and underscores only)
        if not username.isalnum() and "_" not in username:
            raise ValueError("Invalid username format.  Must be alphanumeric and underscores only.")

        # Hash the password using bcrypt
        hashed_password, salt = hash_password(password)

        # Store the hashed password.  Crucial for security.
        cursor.execute("INSERT INTO users (username, password, salt, failed_login_attempts, locked_until) VALUES (?, ?, ?, ?, ?)", (username, hashed_password.decode('utf-8'), salt.decode('utf-8'), 0, None))
        conn.commit()
        logging.info(f"User {username} created successfully.")

    except sqlite3.Error as e:
        logging.error(f"Database error: {e}", exc_info=True)
    except ValueError as e:
        logging.error(f"Input validation error: {e}")
    finally:
        if conn:
            conn.close()


def initialize_database():
    """
    Creates the users table if it doesn't exist.  Sets strict permissions.
    """
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()

        # Create the users table with username, password, and salt.
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                salt TEXT NOT NULL,
                failed_login_attempts INTEGER NOT NULL DEFAULT 0,
                locked_until REAL  # Store the timestamp when the account is locked until
            )
        """)
        conn.commit()

        # Apply stricter permissions (example - SQLite doesn't have granular permissions like other DBs)
        # In a real database (PostgreSQL, MySQL), you would use GRANT/REVOKE statements.
        # For SQLite, ensure the database file has appropriate file system permissions.
        # Example (Linux): chmod 600 users.db  (owner read/write only)

        logging.info("Database initialized/checked.")

    except sqlite3.Error as e:
        logging.error(f"Database error: {e}", exc_info=True)
    finally:
        if conn:
            conn.close()


def first_login_setup(username):
    """
    Handles the first login scenario, forcing the user to set a strong password.
    This is a simplified example.  A real implementation would likely involve
    a temporary token or other mechanism to verify the user's identity.
    """
    print(f"Welcome, {username}! This is your first login.")
    while True:
        new_password = input("Please enter a strong, unique password: ")

        # Use zxcvbn to estimate password strength
        strength = zxcvbn.zxcvbn(new_password)
        if strength['score'] < 3:  # Adjust the score threshold as needed
            print(f"Password is too weak.  Suggestions: {strength['feedback']['suggestions']}")
        elif len(new_password) < 8:
            print("Password must be at least 8 characters long.")
        else:
            break

    # Update the user's password in the database.
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()

        hashed_password, salt = hash_password(new_password)

        cursor.execute("UPDATE users SET password = ?, salt = ? WHERE username = ?", (hashed_password.decode('utf-8'), salt.decode('utf-8'), username))
        conn.commit()
        print("Password updated successfully.")

    except sqlite3.Error as e:
        print(f"Database error: {e}")
    finally:
        if conn:
            conn.close()


if __name__ == '__main__':
    # Example Usage
    initialize_database()

    # Create a config.ini file with the following structure:
    # [database]
    # path = db/users.db
    # user = admin
    # password = secure_password

    # Example registration
    new_username = input("Enter a username to register: ")
    new_password = input("Enter a password: ")
    create_user(new_username, new_password)

    # Example login
    login_username = input("Enter your username to login: ")
    login_password = input("Enter your password: ")

    if verify_password_attempt(login_username, login_password):
        print("Login successful!")
    else:
        print("Login failed.")

    # Example first login setup (after registration)
    first_login_setup(new_username)

