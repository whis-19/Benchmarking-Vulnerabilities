import sqlite3
import bcrypt
import secrets
import os
import re  # For email validation
import logging
import configparser
import zxcvbn

# Configure logging
logging.basicConfig(filename='app.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Configuration
config = configparser.ConfigParser()
config.read('config.ini')

DATABASE_FILE = config.get('Database', 'file', fallback='users.db')
BCRYPT_ROUNDS = config.getint('Security', 'bcrypt_rounds', fallback=12)
MIN_PASSWORD_LENGTH = config.getint('Security', 'min_password_length', fallback=12)
ACCOUNT_LOCKOUT_ATTEMPTS = config.getint('Security', 'account_lockout_attempts', fallback=5)
ACCOUNT_LOCKOUT_TIME = config.getint('Security', 'account_lockout_time', fallback=60) # in seconds

# Initialize zxcvbn
password_strength_meter = zxcvbn.PasswordStrength()


def create_table():
    """Creates the users table if it doesn't exist."""
    conn = None  # Initialize conn to None
    try:
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                first_name TEXT,
                last_name TEXT,
                email TEXT,
                failed_login_attempts INTEGER DEFAULT 0,
                lockout_until DATETIME
            )
        ''')
        conn.commit()
        logging.info("Users table created or already exists.")
    except sqlite3.Error as e:
        logging.error(f"Database error creating table: {e}")
    finally:
        if conn:
            conn.close()


create_table()  # Ensure the table exists when the script runs


def hash_password(password, rounds=BCRYPT_ROUNDS):
    """Hashes the password using bcrypt."""
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(rounds=rounds))
    return hashed_password.decode('utf-8')


def is_valid_email(email):
    """Validates email format using a regular expression."""
    # A more robust email regex (still not perfect, but better)
    email_regex = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    return re.match(email_regex, email) is not None


def check_password_strength(password):
    """Checks password strength using zxcvbn."""
    result = password_strength_meter.test(password)
    return result['score']  # Score ranges from 0 (weak) to 4 (strong)


def register_user(username, password, first_name, last_name, email):
    """Registers a new user in the database."""
    conn = None  # Initialize conn to None
    try:
        # Input validation
        if not (3 <= len(username) <= 50 and re.match("^[a-zA-Z0-9_]+$", username)):
            logging.warning(f"Invalid username format: {username}")
            return "Invalid username. Must be 3-50 characters, alphanumeric and underscores only."

        if len(password) < MIN_PASSWORD_LENGTH:
            logging.warning(f"Password too short: {username}")
            return f"Invalid password. Must be at least {MIN_PASSWORD_LENGTH} characters long."

        password_strength = check_password_strength(password)
        if password_strength < 2:  # Adjust the threshold as needed
            logging.warning(f"Weak password for user: {username}, strength: {password_strength}")
            return "Password is too weak. Please choose a stronger password."

        if not is_valid_email(email):
            logging.warning(f"Invalid email format: {email}")
            return "Invalid email address."

        if not (0 <= len(first_name) <= 50 and re.match("^[a-zA-Z ]*$", first_name)):
            logging.warning(f"Invalid first name format: {first_name}")
            return "Invalid first name. Must be 0-50 characters and contain only letters and spaces."

        if not (0 <= len(last_name) <= 50 and re.match("^[a-zA-Z ]*$", last_name)):
            logging.warning(f"Invalid last name format: {last_name}")
            return "Invalid last name. Must be 0-50 characters and contain only letters and spaces."


        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()

        # Check if username already exists (Account Enumeration Prevention)
        cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
        if cursor.fetchone():
            logging.warning(f"Registration attempt with existing username: {username}")
            return "Registration failed."  # Generic message to prevent enumeration

        # Hash password
        password_hash = hash_password(password)

        # Insert user data into the database
        try:
            cursor.execute('''
                INSERT INTO users (username, password_hash, first_name, last_name, email)
                VALUES (?, ?, ?, ?, ?)
            ''', (username, password_hash, first_name, last_name, email))
            conn.commit()
            logging.info(f"User registered successfully: {username}")
            return "Registration successful!"
        except sqlite3.IntegrityError as e:
            logging.error(f"IntegrityError during registration for user {username}: {e}")
            conn.rollback()
            return "Registration failed."
        except sqlite3.Error as e:
            logging.exception(f"Database error during registration for user {username}: {e}")
            conn.rollback()
            return "Registration failed."


    except Exception as e:
        logging.exception(f"Unexpected error during registration for user {username}: {e}")
        return "Registration failed."  # Generic error message for production
    finally:
        if conn:
            conn.close()


# Example usage (replace with your web framework's input handling)
if __name__ == '__main__':
    # Simulate form data
    username = input("Enter username: ")
    password = input("Enter password: ")
    first_name = input("Enter first name: ")
    last_name = input("Enter last name: ")
    email = input("Enter email: ")

    # Register the user
    registration_result = register_user(username, password, first_name, last_name, email)
    print(registration_result)

