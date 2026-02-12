import argon2
import secrets
import psycopg2  # For PostgreSQL database interaction
import re  # For password complexity validation
import os
import logging
import bleach
import time
import redis

# Configure logging (e.g., to a file)
logging.basicConfig(filename='app.log', level=logging.ERROR)

# Database configuration (replace with your actual credentials)
DB_NAME = os.environ.get("DB_NAME")
DB_USER = os.environ.get("DB_USER")
DB_PASSWORD = os.environ.get("DB_PASSWORD")
DB_HOST = os.environ.get("DB_HOST")
DB_PORT = os.environ.get("DB_PORT")

if not all([DB_NAME, DB_USER, DB_PASSWORD, DB_HOST, DB_PORT]):
    raise EnvironmentError("Database credentials not properly configured.  Please set DB_NAME, DB_USER, DB_PASSWORD, DB_HOST, and DB_PORT environment variables.")

# Redis configuration (replace with your actual credentials)
REDIS_HOST = os.environ.get("REDIS_HOST", "localhost")
REDIS_PORT = int(os.environ.get("REDIS_PORT", 6379))
REDIS_DB = int(os.environ.get("REDIS_DB", 0))

redis_client = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, db=REDIS_DB)

MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_DURATION = 60 * 5  # 5 minutes


def generate_salt():
    """Generates a random salt for password hashing."""
    return secrets.token_bytes(16)  # 16 bytes = 128 bits


def hash_password(password, salt):
    """Hashes the password using Argon2id."""
    password_bytes = password.encode('utf-8')
    ph = argon2.PasswordHasher(
        time_cost=3,  # Adjust for performance/security tradeoff
        memory_cost=65536,  # 64MB
        hash_len=32,  # 32 bytes = 256 bits
        salt_len=16,
        algorithm=argon2.low_level.Type.ID
    )
    return ph.hash(password_bytes, salt=salt)


def verify_password(password, hashed_password, salt):
    """Verifies a password against an Argon2id hash."""
    try:
        ph = argon2.PasswordHasher()
        ph.verify(hashed_password, password.encode('utf-8'))
        return True
    except argon2.exceptions.VerifyMismatchError:
        return False
    except argon2.exceptions.InvalidHash:
        return False  # Handle invalid hash format


def is_account_locked(username):
    """Checks if an account is locked."""
    lockout_key = f"lockout:{username}"
    return redis_client.exists(lockout_key)


def record_failed_login(username):
    """Records a failed login attempt."""
    attempt_key = f"login_attempts:{username}"
    lockout_key = f"lockout:{username}"

    if is_account_locked(username):
        return  # Account is already locked

    attempts = redis_client.incr(attempt_key)
    redis_client.expire(attempt_key, LOCKOUT_DURATION)  # Expire after lockout duration

    if attempts >= MAX_LOGIN_ATTEMPTS:
        redis_client.set(lockout_key, "locked", ex=LOCKOUT_DURATION)  # Lock the account
        logging.warning(f"Account '{username}' locked due to too many failed login attempts.")
        print(f"Account '{username}' locked due to too many failed login attempts.")


def register_user(username, password):
    """Registers a new user by hashing the password and storing the salt and hash in a database."""

    # Input validation (important!)
    if not isinstance(username, str) or not isinstance(password, str):
        raise TypeError("Username and password must be strings.")

    # Sanitize the username
    username = bleach.clean(username)

    if not (3 <= len(username) <= 50):  # Example username length constraint
        raise ValueError("Username must be between 3 and 50 characters.")

    # Password complexity requirements (example)
    if not (8 <= len(password) <= 100):
        raise ValueError("Password must be between 8 and 100 characters.")

    if not re.search(r"[a-z]", password):
        raise ValueError("Password must contain at least one lowercase letter.")
    if not re.search(r"[A-Z]", password):
        raise ValueError("Password must contain at least one uppercase letter.")
    if not re.search(r"[0-9]", password):
        raise ValueError("Password must contain at least one digit.")
    if not re.search(r"[@$!%*#?&]", password):
        raise ValueError("Password must contain at least one special character (@$!%*#?&).")

    # Generate a salt
    salt = generate_salt()

    # Hash the password
    hashed_password = hash_password(password, salt)

    # Store the username, salt, and hashed password securely in a database.
    conn = None
    try:
        conn = psycopg2.connect(dbname=DB_NAME, user=DB_USER, password=DB_PASSWORD, host=DB_HOST, port=DB_PORT)
        cur = conn.cursor()

        # Use parameterized queries to prevent SQL injection
        sql = "INSERT INTO users (username, salt, hashed_password) VALUES (%s, %s, %s)"
        # Convert salt and hashed_password to hex for storage
        cur.execute(sql, (username, salt.hex(), hashed_password))
        conn.commit()
        cur.close()
        logging.info(f"User '{username}' registered successfully.")
        print("User registered successfully.")
        return True  # Indicate registration success

    except psycopg2.Error as e:
        logging.exception("Database error during registration:")  # Log the full error
        print("User registration failed.  Please try again later.")  # Generic message to user
        if conn:
            conn.rollback()  # Rollback in case of error
        return False  # Indicate registration failure
    finally:
        if conn:
            conn.close()


def verify_password_with_rate_limiting(username, password):
    """Verifies a user's password, including rate limiting and account lockout."""

    if is_account_locked(username):
        print(f"Account '{username}' is locked. Please try again later.")
        return False

    conn = None
    try:
        conn = psycopg2.connect(dbname=DB_NAME, user=DB_USER, password=DB_PASSWORD, host=DB_HOST, port=DB_PORT)
        cur = conn.cursor()

        # Use parameterized queries to prevent SQL injection
        sql = "SELECT salt, hashed_password FROM users WHERE username = %s"
        cur.execute(sql, (username,))
        result = cur.fetchone()
        cur.close()

        if result:
            stored_salt_hex, stored_hashed_password = result
            stored_salt = bytes.fromhex(stored_salt_hex)

            # Verify the password
            is_valid = verify_password(password, stored_hashed_password, stored_salt)

            if not is_valid:  # Password verification failed
                record_failed_login(username)
                return False

            # Reset login attempts on successful login
            attempt_key = f"login_attempts:{username}"
            redis_client.delete(attempt_key)
            logging.info(f"Password verified successfully for user '{username}'.")
            return True
        else:
            print(f"User '{username}' not found.")
            return False  # User not found

    except psycopg2.Error as e:
        logging.exception("Database error during password verification:")  # Log the full error
        print("Password verification failed.  Please try again later.")  # Generic message to user
        return False
    finally:
        if conn:
            conn.close()


# Example Usage:
if __name__ == "__main__":
    # Create the 'users' table if it doesn't exist (run only once)
    try:
        conn = psycopg2.connect(dbname=DB_NAME, user=DB_USER, password=DB_PASSWORD, host=DB_HOST, port=DB_PORT)
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                username VARCHAR(50) PRIMARY KEY,
                salt VARCHAR(32) NOT NULL,
                hashed_password VARCHAR(100) NOT NULL  -- Increased length for Argon2 hash
            );
        """)
        conn.commit()
        cur.close()
        conn.close()
        print("Table 'users' created (if it didn't exist).")
    except psycopg2.Error as e:
        print(f"Error creating table: {e}")

    # Registration
    try:
        username = input("Enter username: ")
        password = input("Enter password: ")
        if register_user(username, password):
            print("User registered successfully.")
        else:
            print("User registration failed.")
    except ValueError as e:
        print(f"Registration error: {e}")
    except TypeError as e:
        print(f"Registration error: {e}")
    except EnvironmentError as e:
        print(f"Configuration error: {e}")

    # Verification
    username_to_verify = input("Enter username to verify: ")
    password_to_verify = input("Enter password to verify: ")

    if verify_password_with_rate_limiting(username_to_verify, password_to_verify):
        print("Password verified successfully!")
    else:
        print("Password verification failed.")

