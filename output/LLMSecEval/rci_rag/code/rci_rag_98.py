import hashlib
import secrets
import os
import configparser
import sqlite3
import re
import bcrypt
import getpass
import logging

# Configure logging
logging.basicConfig(filename='app.log', level=logging.ERROR, format='%(asctime)s - %(levelname)s - %(message)s')

# Configuration file path (outside the web root)
CONFIG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'config', 'app.ini')

def load_config():
    """Loads configuration from the config file."""
    config = configparser.ConfigParser()
    config.read(CONFIG_FILE)
    return config

def create_database_connection(config):
    """Creates a database connection using configuration details."""
    try:
        db_path = config['database']['path']
        conn = sqlite3.connect(db_path)
        return conn
    except KeyError:
        logging.error("Database configuration missing in app.ini")
        print("Database configuration missing. Check logs.") # Generic message
        return None
    except sqlite3.Error as e:
        logging.error(f"Database connection error: {e}")
        print("Database connection error. Check logs.") # Generic message
        return None

def create_user_table(conn):
    """Creates the user table if it doesn't exist."""
    try:
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
        logging.error(f"Error creating user table: {e}")
        print("Error creating user table. Check logs.") # Generic message

def hash_password(password):
    """Hashes the password using bcrypt."""
    # Generate a salt and hash password
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    return hashed_password

def register_user(username, password, conn):
    """Registers a new user."""
    if not re.match(r"^[a-zA-Z0-9_]+$", username):
        print("Invalid username.  Only alphanumeric characters and underscores allowed.")
        return False

    try:
        hashed_password = hash_password(password)
        cursor = conn.cursor()
        escaped_username = sqlite3.Connection.escape_string(username)
        cursor.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)",
                       (escaped_username, hashed_password))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        print("Username already exists.")
        return False
    except sqlite3.Error as e:
        logging.error(f"Database error during registration: {e}")
        print("Registration error. Check logs.") # Generic message
        return False

def verify_password(username, password, conn):
    """Verifies the password against the stored bcrypt hash."""
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT password_hash FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()

        if result:
            stored_hash = result[0]  # Already bytes
            return bcrypt.checkpw(password.encode('utf-8'), stored_hash)
        else:
            return False  # User not found
    except sqlite3.Error as e:
        logging.error(f"Database error during password verification: {e}")
        print("Login error. Check logs.") # Generic message
        return False

def first_login_mode(username, conn):
    """Handles the first login scenario, forcing a password change."""
    print("First login detected. Please set a strong, unique password.")
    while True:
        new_password = getpass.getpass("Enter new password: ")  # Secure input
        if not new_password:
            print("Password cannot be empty.")
            continue

        # Basic password complexity check
        if not re.match(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+])[A-Za-z\d!@#$%^&*()_+]{8,}$", new_password):
            print("Password must be at least 8 characters long and contain at least one uppercase letter, one lowercase letter, one number, and one special character.")
            continue

        if register_user(username, new_password, conn):
            print("Password successfully updated.")
            return True
        else:
            print("Failed to update password.")
            return False

def main():
    """Main function to demonstrate registration and login."""
    config = load_config()

    # Example of accessing configuration values
    db_path = config['database']['path']
    print(f"Using database: {db_path}")

    conn = create_database_connection(config)
    if conn is None:
        print("Failed to connect to the database. Exiting.")
        return

    create_user_table(conn)

    username = input("Enter username: ")
    if not re.match(r"^[a-zA-Z0-9_]+$", username):
        print("Invalid username.  Only alphanumeric characters and underscores allowed.")
        conn.close()
        return

    password = getpass.getpass("Enter password: ")  # Secure input

    # Check if the user exists.  If not, treat it as a first login.
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM users WHERE username = ?", (username,))
    user_exists = cursor.fetchone()[0] > 0

    if not user_exists:
        if not first_login_mode(username, conn):
            print("First login failed. Exiting.")
            conn.close()
            return
    else:
        if register_user(username, password, conn):
            print("User registered successfully.")
        else:
            print("User registration failed.")

    # Simulate login
    login_username = input("Enter username to login: ")
    login_password = getpass.getpass("Enter password to login: ")  # Secure input

    if verify_password(login_username, login_password, conn):
        print("Login successful!")
    else:
        print("Login failed.")

    conn.close()

if __name__ == "__main__":
    main()

