import logging
import secrets
import os
import hashlib
import hmac
from typing import Optional

# Configure logging (if not already configured elsewhere)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def log_username(logger: logging.Logger, username: str):
    '''
    Add the username to the log as a warning.  Sanitizes the username to prevent log injection.

    :param logger: The logger object.
    :param username: The username to log.
    '''
    # Sanitize the username to prevent log injection attacks.  This is crucial.
    # Remove any characters that could be interpreted as formatting commands by the logging system.
    sanitized_username = "".join(c for c in username if c.isalnum())  # Allow only alphanumeric characters

    logger.warning(f"User logged in: {sanitized_username}")


def generate_salt() -> str:
    """Generates a random salt for password hashing."""
    return secrets.token_hex(16)  # 16 bytes = 32 hex characters


def hash_password(password: str, salt: str) -> str:
    """Hashes the password using PBKDF2-HMAC-SHA256."""
    # Convert password and salt to bytes
    password_bytes = password.encode('utf-8')
    salt_bytes = salt.encode('utf-8')

    # Use PBKDF2-HMAC-SHA256 for password hashing
    hashed_password = hashlib.pbkdf2_hmac(
        'sha256',
        password_bytes,
        salt_bytes,
        iterations=100000,  # Adjust the number of iterations as needed (higher is better)
        dklen=64  # Desired key length (64 bytes = 512 bits)
    )

    return hashed_password.hex()  # Return the hexadecimal representation of the hash


def verify_password(password: str, stored_hash: str, salt: str) -> bool:
    """Verifies the password against the stored hash and salt."""
    # Hash the provided password using the same salt
    hashed_password = hash_password(password, salt)

    # Compare the generated hash with the stored hash using a constant-time comparison
    return hmac.compare_digest(hashed_password, stored_hash)


def store_credentials(username: str, password: str, db_connection):
    """
    Stores the user's credentials (hashed password and salt) in the database.
    This is a placeholder; replace with your actual database interaction code.
    """
    salt = generate_salt()
    hashed_password = hash_password(password, salt)

    # Example using a hypothetical database connection (replace with your actual DB code)
    try:
        cursor = db_connection.cursor()
        cursor.execute(
            "INSERT INTO users (username, password_hash, salt) VALUES (%s, %s, %s)",
            (username, hashed_password, salt)
        )
        db_connection.commit()
        print(f"User {username} registered successfully.")
    except Exception as e:
        print(f"Error storing credentials: {e}")
        db_connection.rollback()
    finally:
        cursor.close()


def authenticate_user(username: str, password: str, db_connection) -> bool:
    """
    Authenticates the user by verifying the password against the stored hash.
    This is a placeholder; replace with your actual database interaction code.
    """
    try:
        cursor = db_connection.cursor()
        cursor.execute("SELECT password_hash, salt FROM users WHERE username = %s", (username,))
        result = cursor.fetchone()

        if result:
            stored_hash, salt = result
            return verify_password(password, stored_hash, salt)
        else:
            print("User not found.")
            return False
    except Exception as e:
        print(f"Error during authentication: {e}")
        return False
    finally:
        cursor.close()


# Example Usage (replace with your actual application logic)
if __name__ == '__main__':
    # Example setup (replace with your actual database connection)
    import sqlite3
    db_file = "user_database.db"
    db_exists = os.path.exists(db_file)
    db_connection = sqlite3.connect(db_file)
    cursor = db_connection.cursor()

    if not db_exists:
        cursor.execute("""
            CREATE TABLE users (
                username TEXT PRIMARY KEY,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL
            )
        """)
        db_connection.commit()
        print("Database created.")

    logger = logging.getLogger(__name__)

    # Example registration
    new_username = "testuser"
    new_password = "P@$$wOrd"  # Replace with a strong password
    store_credentials(new_username, new_password, db_connection)

    # Example authentication
    username_to_authenticate = "testuser"
    password_to_authenticate = "P@$$wOrd"

    if authenticate_user(username_to_authenticate, password_to_authenticate, db_connection):
        print("Authentication successful!")
        log_username(logger, username_to_authenticate)
    else:
        print("Authentication failed.")

    db_connection.close()

