import hashlib
import os
import configparser
import sqlite3
from cryptography.fernet import Fernet
import secrets
import logging
import re  # For password complexity

# Configure logging
logging.basicConfig(filename='app.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Configuration file path (store outside the web root)
CONFIG_FILE = "/etc/myapp/config.ini"  # Secure location outside web root

def _load_config():
    """Loads configuration from the config file."""
    config = configparser.ConfigParser()
    config.read(CONFIG_FILE)
    decrypt_config_section(config, 'database')  # Decrypt before use
    return config

def _get_hashed_password(password, salt=None):
    """Hashes the password using PBKDF2-HMAC with a random salt."""
    if salt is None:
        salt = os.urandom(16)  # Generate a new random salt

    # Use PBKDF2-HMAC for strong password hashing
    hashed_password = hashlib.pbkdf2_hmac(
        'sha256',  # Use SHA256 for the hash function
        password.encode('utf-8'),  # Convert password to bytes
        salt,  # Provide the salt
        100000  # Number of iterations (adjust as needed for security)
    )
    return salt, hashed_password

def create_user(username, password, db_connection):
    """Creates a new user account in the database.

    Args:
        username: The username for the new account.
        password: The user's password.
        db_connection: A database connection object.
    """
    # Validate username and password
    if not (4 <= len(username) <= 32 and username.isalnum()):
        raise ValueError("Invalid username: must be alphanumeric and 4-32 characters long")
    if not (8 <= len(password) <= 64):
        raise ValueError("Invalid password: must be 8-64 characters long")

    # Add password complexity requirements
    if not re.search(r"[a-z]", password):
        raise ValueError("Password must contain at least one lowercase letter")
    if not re.search(r"[A-Z]", password):
        raise ValueError("Password must contain at least one uppercase letter")
    if not re.search(r"[0-9]", password):
        raise ValueError("Password must contain at least one number")
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        raise ValueError("Password must contain at least one special character")

    salt, hashed_password = _get_hashed_password(password)

    try:
        cursor = db_connection.cursor()
        # Store the salt and hashed password in the database
        cursor.execute(
            "INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)",
            (username, hashed_password, salt)
        )
        db_connection.commit()
        logging.info(f"User '{username}' created successfully.")

    except Exception as e:
        logging.error(f"Error creating user: {e}", exc_info=True)  # Log the full exception
        db_connection.rollback()
        raise  # Re-raise the exception to be handled upstream
    finally:
        cursor.close()


def verify_password(username, password, db_connection):
    """Verifies the user's password against the stored hash.

    Args:
        username: The username to verify.
        password: The password to check.
        db_connection: A database connection object.

    Returns:
        True if the password is correct, False otherwise.
    """
    try:
        cursor = db_connection.cursor()
        cursor.execute("SELECT password_hash, salt FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()

        if result:
            stored_hash, salt = result
            _, hashed_password = _get_hashed_password(password, salt)  # Use the stored salt

            return secrets.compare_digest(hashed_password, stored_hash)  # Compare the hashes

        else:
            logging.info(f"Login attempt with invalid username.") # Generic error message
            return False

    except Exception as e:
        logging.error(f"Error verifying password for user '{username}': {e}", exc_info=True)
        return False
    finally:
        cursor.close()


def isEqual(account1, account2):
    '''
    Compare whether the two accounts are the same.
    This function now assumes that account1 and account2 are usernames.
    It retrieves the password hashes from the database and compares them.
    '''
    config = _load_config()
    db_name = config['database']['name']

    try:
        # Hardcode the database name and use a dedicated user (if possible with SQLite)
        db_connection = sqlite3.connect(db_name)

        cursor = db_connection.cursor()
        cursor.execute("SELECT password_hash, salt FROM users WHERE username = ?", (account1,))
        result1 = cursor.fetchone()
        cursor.execute("SELECT password_hash, salt FROM users WHERE username = ?", (account2,))
        result2 = cursor.fetchone()

        if result1 and result2:
            hash1, salt1 = result1
            hash2, salt2 = result2

            # Compare the salts and hashes using constant-time comparison
            return secrets.compare_digest(salt1, salt2) and secrets.compare_digest(hash1, hash2)
        else:
            logging.warning("One or both accounts not found.")
            return False

    except Exception as e:
        logging.error(f"Error comparing accounts: {e}", exc_info=True)
        return False
    finally:
        if db_connection:
            cursor.close()
            db_connection.close()

def encrypt_config_section(config, section):
    """Encrypts a section of the config file."""
    key = os.environ.get("CONFIG_ENCRYPTION_KEY")  # Get key from environment variable
    if not key:
        raise ValueError("CONFIG_ENCRYPTION_KEY environment variable not set!")
    key = key.encode() # Ensure key is bytes
    f = Fernet(key)

    for k, v in config[section].items():
        encrypted_value = f.encrypt(v.encode()).decode()
        config[section][k] = encrypted_value

def decrypt_config_section(config, section):
    """Decrypts a section of the config file."""
    key = os.environ.get("CONFIG_ENCRYPTION_KEY")  # Get key from environment variable
    if not key:
        raise ValueError("CONFIG_ENCRYPTION_KEY environment variable not set!")
    key = key.encode() # Ensure key is bytes
    f = Fernet(key)

    for k, v in config[section].items():
        decrypted_value = f.decrypt(v.encode()).decode()
        config[section][k] = decrypted_value

# Example Usage (Illustrative - adapt to your specific database and application)
if __name__ == '__main__':
    # Create a dummy SQLite database for testing
    db_name = "test.db"
    db_connection = sqlite3.connect(db_name)
    cursor = db_connection.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password_hash BLOB NOT NULL,
            salt BLOB NOT NULL
        )
    """)
    db_connection.commit()
    cursor.close()
    db_connection.close()

    # Example configuration file creation (DO THIS ONCE, SECURELY)
    if not os.path.exists(CONFIG_FILE):
        config = configparser.ConfigParser()
        config['database'] = {
            'name': db_name,
        }

        # Encrypt the database section
        try:
            # Generate a key (DO THIS ONCE AND STORE SECURELY)
            # key = Fernet.generate_key()
            # with open("encryption.key", "wb") as key_file:
            #     key_file.write(key)
            encrypt_config_section(config, 'database')
        except Exception as e:
            logging.error(f"Error encrypting config section: {e}", exc_info=True)
            raise

        with open(CONFIG_FILE, 'w') as configfile:
            config.write(configfile)
        os.chmod(CONFIG_FILE, 0o600)  # Restrict access to the config file

    # Example usage
    db_connection = sqlite3.connect(db_name)
    try:
        create_user("testuser1", "P@$$wOrd1", db_connection)
        create_user("testuser2", "AnotherP@$$wOrd", db_connection)
    except ValueError as e:
        print(f"Error creating user: {e}")
    except Exception as e:
        print(f"Unexpected error creating user: {e}")
    finally:
        db_connection.close()

    # Compare the accounts
    are_equal = isEqual("testuser1", "testuser1")
    print(f"Accounts are equal: {are_equal}")

    are_equal = isEqual("testuser1", "testuser2")
    print(f"Accounts are equal: {are_equal}")

