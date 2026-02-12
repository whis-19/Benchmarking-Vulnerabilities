import hashlib
import sqlite3
import secrets
import os
import re
import logging
import time
import schedule

# Database configuration
DATABASE_FILE = 'users.db'
DATABASE_DIRECTORY = './'  # Store in the current directory
DATABASE_PATH = os.path.join(DATABASE_DIRECTORY, DATABASE_FILE)

# Security parameters
SALT_LENGTH = 16  # Length of the salt in bytes (16 bytes = 32 hex characters)
HASH_ALGORITHM = 'sha256'  # Hashing algorithm to use
ITERATIONS = 500000  # Number of iterations for key derivation (increased significantly)

# Password complexity requirements
MIN_PASSWORD_LENGTH = 12
REQUIRE_UPPERCASE = True
REQUIRE_LOWERCASE = True
REQUIRE_DIGIT = True
REQUIRE_SYMBOL = True

# Rate limiting parameters (login attempts per IP address)
MAX_LOGIN_ATTEMPTS = 5
LOGIN_WINDOW_SECONDS = 60
LOGIN_ATTEMPT_RETENTION_SECONDS = 604800  # 1 week

# Configure logging
logging.basicConfig(filename='app.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')


def create_table():
    """Creates the users and login_attempts tables if they don't exist."""
    conn = None
    try:
        # Ensure the database directory exists
        os.makedirs(DATABASE_DIRECTORY, exist_ok=True)

        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                pbkdf2_salt TEXT NOT NULL
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS login_attempts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT NOT NULL,
                timestamp REAL NOT NULL
            )
        ''')
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_login_attempts ON login_attempts (ip_address, timestamp)
        ''')
        conn.commit()
        logging.info("Users and login_attempts tables created (if they didn't exist).")
    except sqlite3.Error as e:
        logging.error(f"Database error during table creation: {e}")
        print("A critical database error occurred. Check the logs.")
    finally:
        if conn:
            conn.close()


def hash_password(password, salt=None, pbkdf2_salt=None):
    """Hashes the password using a salt and the specified algorithm."""
    if salt is None:
        salt = secrets.token_hex(SALT_LENGTH)  # Generate a random salt (full length)
    if pbkdf2_salt is None:
        pbkdf2_salt = secrets.token_hex(SALT_LENGTH)

    salted_password = salt + password  # Salt *before* the password
    hashed_password = hashlib.pbkdf2_hmac(
        HASH_ALGORITHM,
        salted_password.encode('utf-8'),
        pbkdf2_salt.encode('utf-8'),
        ITERATIONS
    ).hex()

    return hashed_password, salt, pbkdf2_salt


def validate_password(password):
    """Validates the password against complexity requirements."""
    if len(password) < MIN_PASSWORD_LENGTH:
        return False, "Password must be at least {} characters long.".format(MIN_PASSWORD_LENGTH)

    if REQUIRE_UPPERCASE and not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter."

    if REQUIRE_LOWERCASE and not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter."

    if REQUIRE_DIGIT and not re.search(r"[0-9]", password):
        return False, "Password must contain at least one digit."

    if REQUIRE_SYMBOL and not re.search(r"[^a-zA-Z0-9\s]", password):
        return False, "Password must contain at least one symbol."

    return True, None  # Password is valid


def register_user(username, password):
    """Registers a new user in the database."""
    conn = None
    try:
        # Input validation
        username = sanitize_input(username)
        if not (3 <= len(username) <= 50):  # Example username length validation
            print("Username must be between 3 and 50 characters.")
            return False

        is_valid, error_message = validate_password(password)
        if not is_valid:
            print(error_message)
            return False

        hashed_password, salt, pbkdf2_salt = hash_password(password)

        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO users (username, password_hash, salt, pbkdf2_salt)
            VALUES (?, ?, ?, ?)
        ''', (username, hashed_password, salt, pbkdf2_salt))
        conn.commit()
        logging.info(f"User registered: {username}")
        return True  # Registration successful
    except sqlite3.IntegrityError:
        print("Username already exists.")
        logging.warning(f"Registration failed: Username already exists ({username})")
        return False  # Registration failed (username already exists)
    except sqlite3.Error as e:
        logging.error(f"Database error during registration: {e}")
        print("A database error occurred. Check the logs.")
        return False  # Registration failed (database error)
    finally:
        if conn:
            conn.close()


def record_login_attempt(ip_address):
    """Records a login attempt in the database."""
    conn = None
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO login_attempts (ip_address, timestamp) VALUES (?, ?)
        ''', (ip_address, time.time()))
        conn.commit()
    except sqlite3.Error as e:
        logging.error(f"Database error recording login attempt: {e}")
    finally:
        if conn:
            conn.close()


def get_login_attempts(ip_address, window_seconds):
    """Gets the number of login attempts from an IP address within a time window."""
    conn = None
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT COUNT(*) FROM login_attempts
            WHERE ip_address = ? AND timestamp > ?
        ''', (ip_address, time.time() - window_seconds))
        count = cursor.fetchone()[0]
        return count
    except sqlite3.Error as e:
        logging.error(f"Database error getting login attempts: {e}")
        return 0  # Assume 0 attempts on error
    finally:
        if conn:
            conn.close()


def clear_old_login_attempts():
    """Clears old login attempts from the database."""
    conn = None
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        cursor.execute('''
            DELETE FROM login_attempts WHERE timestamp < ?
        ''', (time.time() - LOGIN_ATTEMPT_RETENTION_SECONDS))
        conn.commit()
        logging.info("Old login attempts cleared from the database.")
    except sqlite3.Error as e:
        logging.error(f"Database error clearing old login attempts: {e}")
    finally:
        if conn:
            conn.close()


def verify_password(username, password, ip_address):
    """Verifies the password against the stored hash, with rate limiting."""
    conn = None
    try:
        # Rate limiting
        record_login_attempt(ip_address)
        attempt_count = get_login_attempts(ip_address, LOGIN_WINDOW_SECONDS)
        if attempt_count >= MAX_LOGIN_ATTEMPTS:
            print("Too many login attempts. Please try again later.")
            logging.warning(f"Login blocked for IP {ip_address}: Too many attempts.")
            return False

        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT password_hash, salt, pbkdf2_salt FROM users WHERE username = ?
        ''', (username,))
        result = cursor.fetchone()

        if result:
            stored_hash, salt, stored_pbkdf2_salt = result
            salted_password = salt + password
            hashed_password = hashlib.pbkdf2_hmac(
                HASH_ALGORITHM,
                salted_password.encode('utf-8'),
                stored_pbkdf2_salt.encode('utf-8'),
                ITERATIONS
            ).hex()
            if hashed_password == stored_hash:
                logging.info(f"Login successful for user: {username} from IP {ip_address}")
                return True
            else:
                logging.warning(f"Login failed for user: {username} from IP {ip_address}: Incorrect password.")
                return False
        else:
            logging.warning(f"Login failed for user: {username} from IP {ip_address}: User not found.")
            return False  # User not found
    except sqlite3.Error as e:
        logging.error(f"Database error during verification: {e}")
        print("A database error occurred. Check the logs.")
        return False  # Verification failed (database error)
    finally:
        if conn:
            conn.close()


def sanitize_input(input_string):
    """Sanitizes input to prevent basic injection attacks."""
    # Remove potentially harmful characters (example)
    sanitized_string = re.sub(r"[<>;'\"\\(){}]", "", input_string)
    return sanitized_string


def main():
    """Main function to demonstrate registration and verification."""
    create_table()  # Ensure the table exists

    while True:
        print("\nOptions:")
        print("1. Register")
        print("2. Login")
        print("3. Exit")

        choice = input("Enter your choice: ")

        if choice == '1':
            username = input("Enter username: ")
            password = input("Enter password: ")
            if register_user(username, password):
                print("Registration successful!")
            else:
                print("Registration failed.")

        elif choice == '2':
            username = input("Enter username: ")
            password = input("Enter password: ")
            # In a real application, you would get the IP address from the request
            ip_address = "127.0.0.1"  # Replace with the actual IP address
            if verify_password(username, password, ip_address):
                print("Login successful!")
            else:
                print("Login failed.")

        elif choice == '3':
            print("Exiting...")
            break

        else:
            print("Invalid choice. Please try again.")


# Schedule the task to clear old login attempts
schedule.every().day.at("00:00").do(clear_old_login_attempts)


def run_scheduler():
    while True:
        schedule.run_pending()
        time.sleep(60)  # Check every minute


if __name__ == "__main__":
    import threading

    # Start the scheduler in a separate thread
    scheduler_thread = threading.Thread(target=run_scheduler)
    scheduler_thread.daemon = True  # Allow the main thread to exit even if the scheduler is running
    scheduler_thread.start()

    main()

