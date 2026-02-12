import hashlib
import sqlite3
import secrets
import os
import bcrypt  # Import bcrypt
import re
import logging  # Import logging
import time

# Database configuration
DATABASE_FILE = 'user_database.db'

# Configure logging
logging.basicConfig(filename='app.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Constants for rate limiting
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_DURATION = 60  # seconds

# --- Helper Functions ---

def generate_salt():
    """Generates a cryptographically secure random salt."""
    return secrets.token_hex(16)  # 16 bytes = 32 hex characters


# def hash_password(password, salt):  # REMOVE THIS FUNCTION
#     """Hashes the password using SHA-256 with the provided salt."""
#     salted_password = salt.encode('utf-8') + password.encode('utf-8')
#     hashed_password = hashlib.sha256(salted_password).hexdigest()
#     return hashed_password


def create_table():
    """Creates the users table if it doesn't exist."""
    conn = None  # Initialize conn to None
    try:
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                # salt TEXT NOT NULL  # No longer needed with bcrypt
                failed_login_attempts INTEGER DEFAULT 0,
                lockout_until REAL DEFAULT 0
            )
        """)
        conn.commit()
        logging.info("Users table created (if it didn't exist).")
    except sqlite3.Error as e:
        logging.error(f"Database error: {e}")
        print(f"Database error: {e}")
    finally:
        if conn:
            conn.close()


# --- User Registration Function ---

def register_user(username, password):
    """Registers a new user in the database."""
    conn = None  # Initialize conn to None
    try:
        # Input validation (basic example)
        if not (4 <= len(username) <= 50):
            raise ValueError("Username must be between 4 and 50 characters.")
        if not (8 <= len(password) <= 100):
            raise ValueError("Password must be between 8 and 100 characters.")

        # Validate username format using a regular expression
        if not re.match(r"^[a-zA-Z0-9_]+$", username):
            raise ValueError("Username must contain only alphanumeric characters and underscores.")


        # Generate salt and hash the password
        # salt = generate_salt()  # No longer needed with bcrypt
        # password_hash = hash_password(password, salt)  # REMOVE THIS LINE
        password_hash = hash_password_bcrypt(password)
        if not password_hash:
            raise ValueError("Password hashing failed.")


        # Connect to the database
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()

        # Insert the user data into the database
        # Parameterized queries prevent SQL injection by treating user input as data, not code.
        # The database driver handles escaping and quoting the data appropriately.
        cursor.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)",
                       (username, password_hash)) # Store bcrypt hash, no salt needed
        conn.commit()
        print(f"User '{username}' registered successfully.")
        logging.info(f"User '{username}' registered successfully.")

    except sqlite3.IntegrityError:
        print(f"Username '{username}' already exists.")
        logging.warning(f"Registration failed: Username '{username}' already exists.")
    except ValueError as e:
        print(f"Input error: {e}")
        logging.warning(f"Registration failed: Input error: {e}")
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        logging.error(f"Database error: {e}")
    except Exception as e:
        print(f"Unexpected error: {e}")
        logging.error(f"Unexpected error during registration: {e}")
    finally:
        if conn:
            conn.close()


# --- Main Execution ---

if __name__ == "__main__":
    # Create the users table if it doesn't exist
    create_table()

    # Get user input (in a real application, use a proper UI)
    username = input("Enter username: ")
    password = input("Enter password: ")

    # Register the user
    register_user(username, password)


# --- Example Verification (for demonstration - separate function in real app) ---
def verify_password(username, password):
    """Verifies a user's password against the stored hash."""
    conn = None
    try:
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()

        # Check if account is locked
        cursor.execute("SELECT lockout_until FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()

        if result:
            lockout_until = result[0]
            if lockout_until and lockout_until > time.time():
                print("Account is locked. Please try again later.")
                logging.warning(f"Account locked for user: {username}")
                return False

        cursor.execute("SELECT password_hash, failed_login_attempts FROM users WHERE username = ?", (username,)) # Only need the hash
        result = cursor.fetchone()

        if result:
            stored_password_hash, failed_login_attempts = result
            # hashed_password = hash_password(password, salt)  # REMOVE THIS LINE

            if verify_password_bcrypt(password, stored_password_hash): # Use bcrypt verification
                print("Password verified successfully!")
                logging.info(f"Password verified successfully for user: {username}")

                # Reset failed login attempts on successful login
                cursor.execute("UPDATE users SET failed_login_attempts = 0, lockout_until = 0 WHERE username = ?", (username,))
                conn.commit()

                return True
            else:
                print("Incorrect password.")
                logging.warning(f"Incorrect password attempt for user: {username}")

                # Increment failed login attempts
                failed_login_attempts += 1
                if failed_login_attempts >= MAX_LOGIN_ATTEMPTS:
                    lockout_until = time.time() + LOCKOUT_DURATION
                    print(f"Account locked for {LOCKOUT_DURATION} seconds.")
                    logging.warning(f"Account locked for user: {username}")
                else:
                    lockout_until = 0  # Reset lockout if not exceeding max attempts

                cursor.execute("UPDATE users SET failed_login_attempts = ?, lockout_until = ? WHERE username = ?", (failed_login_attempts, lockout_until, username))
                conn.commit()

                return False
        else:
            print("User not found.")
            logging.warning(f"User not found during verification: {username}")
            return False

    except sqlite3.Error as e:
        print(f"Database error: {e}")
        logging.error(f"Database error during verification: {e}")
        return False
    except Exception as e:
        print(f"Unexpected error: {e}")
        logging.error(f"Unexpected error during verification: {e}")
        return False
    finally:
        if conn:
            conn.close()

    # Example usage of verification (after registration)
    if __name__ == "__main__":
        if os.path.exists(DATABASE_FILE): # Only run if the database exists
            username_to_verify = input("Enter username to verify: ")
            password_to_verify = input("Enter password to verify: ")
            verify_password(username_to_verify, password_to_verify)


# --- Example using bcrypt (replace SHA-256) ---
def hash_password_bcrypt(password):
    """Hashes the password using bcrypt."""
    try:
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        return hashed_password.decode('utf-8')  # Store as string
    except Exception as e:
        print(f"Error hashing password with bcrypt: {e}")
        logging.error(f"Error hashing password with bcrypt: {e}")
        return None

def verify_password_bcrypt(password, stored_hash):
    """Verifies a password against a bcrypt hash."""
    try:
        return bcrypt.checkpw(password.encode('utf-8'), stored_hash.encode('utf-8'))
    except Exception as e:
        print(f"Error verifying password with bcrypt: {e}")
        logging.error(f"Error verifying password with bcrypt: {e}")
        return False

# Example usage of bcrypt (replace SHA-256 calls)
# password_hash = hash_password_bcrypt(password)
# if verify_password_bcrypt(password, stored_password_hash):
#     # Password is correct

# --- Important Considerations and Improvements for Production: ---

# Password Reset Mechanism: Implement a secure password reset mechanism. This should involve sending a unique, time-limited token to the user's email address.  Store a hash of the token in the database (e.g., using SHA-256 or bcrypt) instead of the token itself.  The token should expire after a short period (e.g., 1 hour) to prevent it from being used indefinitely.  Use a cryptographically secure random token for the reset link.

# Security Headers: Set appropriate security headers in your web server configuration to protect against common web attacks.  Examples:
#   - Content-Security-Policy:  Helps prevent XSS attacks by controlling the sources from which the browser is allowed to load resources.
#   - X-Frame-Options:  Protects against clickjacking.
#   - Strict-Transport-Security:  Enforces HTTPS.
#   - X-Content-Type-Options:  Prevents MIME sniffing.

# Testing: Write unit tests and integration tests to ensure that your code is working correctly and that it is secure.  Examples:
#   - Unit tests: Test individual functions (e.g., hash_password, verify_password).
#   - Integration tests: Test the interaction between registration and login.
#   - Security tests: Test for SQL injection, XSS, and brute-force attacks.  Tools like OWASP ZAP can be helpful for this.

# Input Validation: Use regular expressions for more complex input validation.  For example:
#   import re
#   if not re.match(r"^[a-zA-Z0-9_]+$", username):
#       raise ValueError("Username must contain only alphanumeric characters and underscores.")
# Be careful with overly complex regular expressions, which can be vulnerable to ReDoS attacks.

