import sqlite3
import os
import configparser
import secrets
import logging
import time
from itsdangerous import URLSafeTimedSerializer
import bcrypt

# Configuration
config = configparser.ConfigParser()
config.read('config.ini')

DATABASE_PATH = config['database']['path']
MAX_PASSWORD_LENGTH = 128  # Limit password length to prevent DoS
FAILED_LOGIN_ATTEMPTS = 5
LOCKOUT_DURATION = 900  # 15 minutes in seconds
MIN_PASSWORD_LENGTH = 8
REQUIRE_UPPERCASE = True
REQUIRE_LOWERCASE = True
REQUIRE_DIGIT = True
REQUIRE_SPECIAL = True

# Logging Configuration
logging.basicConfig(filename='security.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Initialize the serializer for password reset tokens
SECRET_KEY = config['security']['secret_key']  # Store this securely!
ts = URLSafeTimedSerializer(SECRET_KEY)

def create_database():
    """Creates the database and user table if they don't exist."""
    try:
        with sqlite3.connect(DATABASE_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    failed_attempts INTEGER DEFAULT 0,
                    lockout_until REAL
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS password_reset_tokens (
                    user_id INTEGER NOT NULL,
                    token_hash TEXT NOT NULL,
                    expiration_time REAL NOT NULL,
                    FOREIGN KEY (user_id) REFERENCES users (id)
                )
            """)
            conn.commit()
        logging.info("Database and tables created/verified successfully.")
    except Exception as e:
        logging.error(f"Error creating database: {e}")
        raise  # Re-raise the exception to halt execution

def hash_password(password):
    """Hashes the password using bcrypt."""
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    return hashed_password.decode('utf-8')  # Store as string

def verify_password(password, stored_hash):
    """Verifies the password against the stored bcrypt hash."""
    return bcrypt.checkpw(password.encode('utf-8'), stored_hash.encode('utf-8'))

def validate_password_complexity(password):
    """Validates password complexity based on defined requirements."""
    if len(password) < MIN_PASSWORD_LENGTH:
        return False, "Password must be at least {} characters long.".format(MIN_PASSWORD_LENGTH)

    if REQUIRE_UPPERCASE and not any(c.isupper() for c in password):
        return False, "Password must contain at least one uppercase character."

    if REQUIRE_LOWERCASE and not any(c.islower() for c in password):
        return False, "Password must contain at least one lowercase character."

    if REQUIRE_DIGIT and not any(c.isdigit() for c in password):
        return False, "Password must contain at least one digit."

    if REQUIRE_SPECIAL and not any(not c.isalnum() for c in password):
        return False, "Password must contain at least one special character."

    return True, None

def create_user(username, password):
    """Creates a new user account."""
    create_database()  # Ensure the database exists

    # Input Validation
    if not (4 <= len(username) <= 32 and username.isalnum()):  # Example username validation
        logging.warning(f"Invalid username format: {username}")
        print("Invalid username format.  Must be alphanumeric and 4-32 characters.")
        return False

    if len(password) > MAX_PASSWORD_LENGTH:
        logging.warning(f"Password exceeds maximum length: {len(password)}")
        print(f"Password exceeds maximum allowed length ({MAX_PASSWORD_LENGTH}).")
        return False

    complexity_valid, message = validate_password_complexity(password)
    if not complexity_valid:
        logging.warning(f"Password complexity requirements not met: {message}")
        print(message)
        return False

    password_hash = hash_password(password)

    try:
        with sqlite3.connect(DATABASE_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)",
                           (username, password_hash))
            conn.commit()
        logging.info(f"User created successfully: {username}")
        return True  # User creation successful
    except sqlite3.IntegrityError:
        logging.warning(f"Username already exists: {username}")
        print("Username already exists.")  # Do not log the username.
        return False # User creation failed (username exists)
    except Exception as e:
        logging.error(f"Error creating user: {e}") # Do not log the username or password.
        print(f"Error creating user: {e}")
        return False # User creation failed (other error)

def verify_login(username, password):
    """Verifies the password against the stored hash."""
    try:
        with sqlite3.connect(DATABASE_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id, password_hash, failed_attempts, lockout_until FROM users WHERE username = ?", (username,))
            result = cursor.fetchone()

        if result:
            user_id, stored_password_hash, failed_attempts, lockout_until = result

            # Account Locking Check
            if lockout_until and time.time() < lockout_until:
                logging.warning(f"Account locked for user: {username}")
                print("Account is locked. Please try again later.")
                return False

            if verify_password(password, stored_password_hash):
                # Reset failed attempts on successful login
                with sqlite3.connect(DATABASE_PATH) as conn:
                    cursor = conn.cursor()
                    cursor.execute("UPDATE users SET failed_attempts = 0, lockout_until = NULL WHERE username = ?", (username,))
                    conn.commit()
                logging.info(f"Login successful for user: {username}")
                return True
            else:
                # Increment failed attempts
                with sqlite3.connect(DATABASE_PATH) as conn:
                    cursor = conn.cursor()
                    cursor.execute("UPDATE users SET failed_attempts = failed_attempts + 1 WHERE username = ?", (username,))
                    conn.commit()

                    # Check if account should be locked
                    cursor.execute("SELECT failed_attempts FROM users WHERE username = ?", (username,))
                    failed_attempts = cursor.fetchone()[0]
                    if failed_attempts >= FAILED_LOGIN_ATTEMPTS:
                        lockout_time = time.time() + LOCKOUT_DURATION
                        cursor.execute("UPDATE users SET lockout_until = ? WHERE username = ?", (lockout_time, username,))
                        conn.commit()
                        logging.warning(f"Account locked for user: {username}")
                        print("Too many failed login attempts. Account locked.")
                logging.warning(f"Failed login attempt for user: {username}")
                return False
        else:
            logging.warning(f"User not found: {username}")
            return False  # User not found
    except Exception as e:
        logging.error(f"Error verifying password: {e}") # Do not log the username or password.
        print(f"Error verifying password: {e}")
        return False

def generate_password_reset_token(username):
    """Generates a password reset token for the given username."""
    try:
        with sqlite3.connect(DATABASE_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
            result = cursor.fetchone()

            if not result:
                logging.warning(f"User not found when generating reset token: {username}")
                return None

            user_id = result[0]
            token = ts.dumps(username, salt='password-reset-salt')
            expiration_time = time.time() + 3600  # Token expires in 1 hour

            # Hash the token before storing it
            token_hash = hashlib.sha256(token.encode('utf-8')).hexdigest()

            # Store the hashed token in the database
            cursor.execute("INSERT INTO password_reset_tokens (user_id, token_hash, expiration_time) VALUES (?, ?, ?)",
                           (user_id, token_hash, expiration_time))
            conn.commit()

            logging.info(f"Password reset token generated for user: {username}")
            return token
    except Exception as e:
        logging.error(f"Error generating password reset token: {e}")
        print(f"Error generating password reset token: {e}")
        return None

def verify_password_reset_token(token):
    """Verifies the password reset token and returns the username if valid."""
    try:
        username = ts.loads(token, salt='password-reset-salt', max_age=3600)
        token_hash = hashlib.sha256(token.encode('utf-8')).hexdigest()

        with sqlite3.connect(DATABASE_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT u.username
                FROM users u
                JOIN password_reset_tokens prt ON u.id = prt.user_id
                WHERE u.username = ? AND prt.token_hash = ? AND prt.expiration_time > ?
            """, (username, token_hash, time.time()))

            result = cursor.fetchone()

            if result:
                # Invalidate the token after successful verification
                cursor.execute("""
                    DELETE FROM password_reset_tokens
                    WHERE token_hash = ?
                """, (token_hash,))
                conn.commit()

                logging.info(f"Password reset token verified successfully for user: {username}")
                return username
            else:
                logging.warning("Invalid or expired password reset token.")
                return None
    except Exception as e:
        logging.error(f"Error verifying password reset token: {e}")
        print(f"Error verifying password reset token: {e}")
        return None

def reset_password(username, new_password):
    """Resets the password for the given username."""
    if len(new_password) > MAX_PASSWORD_LENGTH:
        logging.warning(f"Password exceeds maximum length: {len(new_password)}")
        print(f"Password exceeds maximum allowed length ({MAX_PASSWORD_LENGTH}).")
        return False

    complexity_valid, message = validate_password_complexity(new_password)
    if not complexity_valid:
        logging.warning(f"Password complexity requirements not met: {message}")
        print(message)
        return False

    password_hash = hash_password(new_password)

    try:
        with sqlite3.connect(DATABASE_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE users SET password_hash = ? WHERE username = ?",
                           (password_hash, username))
            conn.commit()
        logging.info(f"Password reset successfully for user: {username}")
        print("Password reset successfully.")
        return True
    except Exception as e:
        logging.error(f"Error resetting password: {e}")
        print(f"Error resetting password: {e}")
        return False

# Example Usage (Registration, Login, and Password Reset)
if __name__ == "__main__":
    # Create a config.ini file (outside the source code directory)
    # with the following structure:
    # [database]
    # path = users.db
    # [security]
    # secret_key = YourSecretKeyForPasswordResetTokens

    # IMPORTANT: Ensure the config.ini file has restrictive permissions (e.g., 600)
    # so that only the user running this script can read it.

    username = input("Enter username: ")
    password = input("Enter password: ")

    if create_user(username, password):
        print("User created successfully.")

        # Simulate login
        login_username = input("Enter username to login: ")
        login_password = input("Enter password to login: ")

        if verify_login(login_username, login_password):
            print("Login successful!")
        else:
            print("Login failed.")

        # Simulate password reset request
        reset_token = generate_password_reset_token(username)
        if reset_token:
            print(f"Password reset token generated: {reset_token}")
            # Simulate sending the token to the user via email

            # Simulate user clicking the link and entering a new password
            new_password = input("Enter new password for reset: ")
            verified_username = verify_password_reset_token(reset_token)
            if verified_username:
                if reset_password(verified_username, new_password):
                    print("Password reset successfully!")
                else:
                    print("Password reset failed.")
            else:
                print("Invalid password reset token.")
        else:
            print("Failed to generate password reset token.")

    else:
        print("User creation failed.")

