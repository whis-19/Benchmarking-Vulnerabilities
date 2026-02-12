import sqlite3
import os
import configparser
import re
import time
import logging
import bcrypt  # Import bcrypt

# Configuration loading
config = configparser.ConfigParser()
config.read('config.ini')  # Store database credentials and other sensitive info here

# Use environment variables for sensitive data
DATABASE_PATH = os.environ.get('DATABASE_PATH', config['database']['path'])  # Fallback to config.ini
DATABASE_USER = os.environ.get('DATABASE_USER', config['database']['user'])  # Fallback to config.ini
DATABASE_PASSWORD = os.environ.get('DATABASE_PASSWORD', config['database']['password'])  # Fallback to config.ini
LOGIN_ATTEMPT_LIMIT = int(os.environ.get('LOGIN_ATTEMPT_LIMIT', config['security']['login_attempt_limit']))
LOCKOUT_DURATION = int(os.environ.get('LOCKOUT_DURATION', config['security']['lockout_duration'])) #seconds

# Logging setup
logging.basicConfig(filename='security.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# In-memory dictionary to store failed login attempts per IP address
failed_login_attempts_ip = {}
IP_RATE_LIMIT = 5  # Maximum failed attempts per IP
IP_LOCKOUT_DURATION = 60  # Lockout duration in seconds

def hash_password(password):
    """Hashes the password using bcrypt."""
    hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    return hashed.decode('utf-8')  # Store as string

def verify_password_bcrypt(password, stored_hash):
    """Verifies the password against the stored bcrypt hash."""
    return bcrypt.checkpw(password.encode('utf-8'), stored_hash.encode('utf-8'))


def create_user(username, password):
    """
    Creates a new user account in the database.  Hashes the password before storing.
    Uses parameterized queries to prevent SQL injection.
    """
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()

        # Hash the password using bcrypt
        hashed_password = hash_password(password)

        # Store the hashed password.  Crucial for security.
        cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password))
        conn.commit()
        print(f"User {username} created successfully.")
        logging.info(f"User {username} created successfully.")

    except sqlite3.Error as e:
        logging.error(f"Database error creating user {username}: {e}")
        print("An error occurred. Please try again later.") # Generic message
    finally:
        if conn:
            conn.close()


def verify_password(username, password, ip_address):
    """
    Verifies a user's password against the stored hash.
    Implements rate limiting to prevent brute-force attacks.
    """
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()

        # Check IP-based rate limiting
        if ip_address in failed_login_attempts_ip:
            last_failed_time, attempts = failed_login_attempts_ip[ip_address]
            if time.time() - last_failed_time < IP_LOCKOUT_DURATION and attempts >= IP_RATE_LIMIT:
                print("Too many failed login attempts from your IP. Please try again later.")
                logging.warning(f"Login blocked from IP {ip_address} due to rate limiting.")
                return False

        # Check if the account is locked
        cursor.execute("SELECT last_failed_login, failed_login_attempts FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()

        if result:
            last_failed_login, failed_login_attempts = result
            if last_failed_login:
                time_since_last_failure = time.time() - last_failed_login
                if time_since_last_failure < LOCKOUT_DURATION and failed_login_attempts >= LOGIN_ATTEMPT_LIMIT:
                    print("Account locked. Please try again later.")
                    logging.warning(f"Account {username} locked due to excessive failed login attempts.")
                    return False

        cursor.execute("SELECT password FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()

        if result:
            stored_password = result[0]

            if verify_password_bcrypt(password, stored_password):
                # Reset failed login attempts on successful login
                cursor.execute("UPDATE users SET failed_login_attempts = 0, last_failed_login = NULL WHERE username = ?", (username,))
                conn.commit()
                logging.info(f"User {username} logged in successfully.")
                # Reset IP-based attempts on successful login
                if ip_address in failed_login_attempts_ip:
                    del failed_login_attempts_ip[ip_address]
                return True
            else:
                # Increment failed login attempts
                cursor.execute("UPDATE users SET failed_login_attempts = failed_login_attempts + 1, last_failed_login = ? WHERE username = ?", (time.time(), username))
                conn.commit()
                logging.warning(f"Failed login attempt for user {username}.")

                # Update IP-based attempts
                if ip_address in failed_login_attempts_ip:
                    last_failed_time, attempts = failed_login_attempts_ip[ip_address]
                    failed_login_attempts_ip[ip_address] = (time.time(), attempts + 1)
                else:
                    failed_login_attempts_ip[ip_address] = (time.time(), 1)

                return False
        else:
            logging.warning(f"Login attempt for non-existent user {username}.")
            # Update IP-based attempts even for non-existent users
            if ip_address in failed_login_attempts_ip:
                last_failed_time, attempts = failed_login_attempts_ip[ip_address]
                failed_login_attempts_ip[ip_address] = (time.time(), attempts + 1)
            else:
                failed_login_attempts_ip[ip_address] = (time.time(), 1)
            return False  # User not found

    except sqlite3.Error as e:
        logging.error(f"Database error verifying password for user {username}: {e}")
        print("An error occurred. Please try again later.") # Generic message
        return False
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
                failed_login_attempts INTEGER DEFAULT 0,
                last_failed_login REAL
            )
        """)
        conn.commit()

        # Apply stricter permissions (example - SQLite doesn't have granular permissions like other DBs)
        # In a real database (PostgreSQL, MySQL), you would use GRANT/REVOKE statements.
        # For SQLite, ensure the database file has appropriate file system permissions.
        # Example (Linux): chmod 600 users.db  (owner read/write only)

        print("Database initialized/checked.")
        logging.info("Database initialized/checked.")

    except sqlite3.Error as e:
        logging.error(f"Database error initializing database: {e}")
        print("An error occurred. Please try again later.") # Generic message
    finally:
        if conn:
            conn.close()


def is_strong_password(password):
    """
    Checks if a password meets certain strength criteria.
    """
    if len(password) < 8:
        return False
    if not re.search("[a-z]", password):
        return False
    if not re.search("[A-Z]", password):
        return False
    if not re.search("[0-9]", password):
        return False
    if not re.search("[!@#$%^&*()]", password):  # Example special characters
        return False
    return True


def is_valid_username(username):
    """
    Validates the username to prevent XSS and other issues.
    """
    if not re.match("^[a-zA-Z0-9_]+$", username):
        return False
    if len(username) > 32: # Limit username length
        return False
    return True


def first_login_setup(username):
    """
    Handles the first login scenario, forcing the user to set a strong password.
    This is a simplified example.  A real implementation would likely involve
    a temporary token or other mechanism to verify the user's identity.
    """
    print(f"Welcome, {username}! This is your first login.")
    while True:
        new_password = input("Please enter a strong, unique password: ")
        if not is_strong_password(new_password):
            print("Password must be at least 8 characters long and include uppercase, lowercase, numbers, and special characters.")
        else:
            break

    # Update the user's password in the database.
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()

        hashed_password = hash_password(new_password)

        cursor.execute("UPDATE users SET password = ? WHERE username = ?", (hashed_password, username))
        conn.commit()
        print("Password updated successfully.")
        logging.info(f"Password updated successfully for user {username}.")

    except sqlite3.Error as e:
        logging.error(f"Database error updating password for user {username}: {e}")
        print("An error occurred. Please try again later.") # Generic message
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
    # [security]
    # login_attempt_limit = 3
    # lockout_duration = 60

    # Example registration
    new_username = input("Enter a username to register: ")
    if not is_valid_username(new_username):
        print("Invalid username.  Must be alphanumeric and underscores only, and less than 32 characters.")
    else:
        new_password = input("Enter a password: ")
        if not is_strong_password(new_password):
            print("Password must be at least 8 characters long and include uppercase, lowercase, numbers, and special characters.")
        else:
            create_user(new_username, new_password)

            # Example login
            login_username = input("Enter your username to login: ")
            login_password = input("Enter your password: ")
            # Simulate getting the user's IP address
            ip_address = "127.0.0.1"  # Replace with actual IP retrieval in a real application

            if verify_password(login_username, login_password, ip_address):
                print("Login successful!")
                # Example first login setup (after registration)
                first_login_setup(new_username)
            else:
                print("Login failed.")

