import logging
import os
import json
import re  # For input validation
import bcrypt  # For password hashing
from cryptography.fernet import Fernet, MultiFernet  # For encryption and key rotation
# from cryptography.fernet import MultiFernet # For key rotation
# Import KMS client library (e.g., boto3 for AWS KMS)

# Configuration file path (outside the source code directory)
CONFIG_FILE = "/etc/myapp/config.json"  # Example location

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def load_config(config_file):
    """Loads configuration from a secure JSON file."""
    try:
        with open(config_file, "r") as f:
            config = json.load(f)
        return config
    except FileNotFoundError:
        logger.error(f"Configuration file not found: {config_file}")
        raise  # Re-raise to halt execution if config is essential
    except json.JSONDecodeError:
        logger.error(f"Invalid JSON format in configuration file: {config_file}")
        raise
    except Exception as e:
        logger.error(f"Error loading config: {e}")
        raise

def get_fernet_key():  # Removed config parameter
    """Retrieves the Fernet key from a KMS or environment variable."""
    # Example using environment variable (less secure than KMS)
    key = os.environ.get("FERNET_KEY")
    if not key:
        logger.error("Fernet key not found in environment variable.")
        raise ValueError("Fernet key not found.")
    return key

    # Example using AWS KMS (replace with your KMS implementation)
    # kms_client = boto3.client('kms')
    # response = kms_client.decrypt(CiphertextBlob=b64decode(config['encrypted_fernet_key']))
    # return response['Plaintext'].decode('utf-8')

def encrypt_data(data, key):
    """Encrypts data using Fernet encryption."""
    try:
        f = Fernet(key.encode()) # Key must be bytes
        encrypted_data = f.encrypt(data.encode())
        return encrypted_data.decode()
    except Exception as e:
        logger.error(f"Encryption error: {e}")
        raise

def decrypt_data(encrypted_data, key):
    """Decrypts data using Fernet encryption."""
    try:
        f = Fernet(key.encode()) # Key must be bytes
        decrypted_data = f.decrypt(encrypted_data.encode())
        return decrypted_data.decode()
    except Exception as e:
        logger.error(f"Decryption error: {e}")
        raise

def hash_password(password):
    """Hashes a password using bcrypt."""
    try:
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        return hashed_password.decode('utf-8')  # Store as string
    except Exception as e:
        logger.error(f"Password hashing error: {e}")
        raise

def verify_password(password, stored_hash):
    """Verifies a password against a stored bcrypt hash."""
    try:
        return bcrypt.checkpw(password.encode('utf-8'), stored_hash.encode('utf-8'))
    except Exception as e:
        logger.error(f"Password verification error: {e}")
        return False # Or raise an exception, depending on the desired behavior

def log_username(username):
    '''
    Add the username to the log as a warning.  However, due to security concerns,
    we will only log a generic message indicating a user-related event.  The
    actual username is NOT logged.

    :param username: The username (not logged directly).
    '''
    logger.warning("A user-related event occurred.")  # Generic message
    # Consider logging a user ID instead of username if absolutely necessary,
    # and if the user ID is not considered sensitive.  Even then, be cautious.
    # Example (if user_id is available):
    # logger.warning(f"User event occurred for user ID: {user_id}")

def validate_username(username):
    """Validates the username."""
    if not isinstance(username, str):
        return False, "Username must be a string."
    if len(username) < 3 or len(username) > 50:
        return False, "Username must be between 3 and 50 characters."
    if not re.match("^[a-zA-Z0-9_]+$", username):  # Only allow alphanumeric and underscore
        return False, "Username can only contain alphanumeric characters and underscores."
    return True, None

def validate_password(password):
    """Validates the password."""
    if not isinstance(password, str):
        return False, "Password must be a string."
    if len(password) < 12:
        return False, "Password must be at least 12 characters long."
    if not re.search("[a-z]", password):
        return False, "Password must contain at least one lowercase letter."
    if not re.search("[A-Z]", password):
        return False, "Password must contain at least one uppercase letter."
    if not re.search("[0-9]", password):
        return False, "Password must contain at least one number."
    if not re.search("[!@#$%^&*(),.?\":{}|<>]", password):
        return False, "Password must contain at least one special character."
    return True, None

def register_user(username, password): # Removed config parameter
    """Registers a new user, storing the password securely."""
    try:
        # Validate inputs
        username_valid, username_error = validate_username(username)
        if not username_valid:
            raise ValueError(f"Invalid username: {username_error}")

        password_valid, password_error = validate_password(password)
        if not password_valid:
            raise ValueError(f"Invalid password: {password_error}")

        fernet_key = get_fernet_key() # Get key from KMS or env var
        hashed_password = hash_password(password)
        encrypted_username = encrypt_data(username, fernet_key)

        # Store encrypted_username and hashed_password in a secure database
        # (replace with your actual database interaction)
        # Example:
        # database.store_user(encrypted_username, hashed_password)
        print(f"User registered (encrypted username): {encrypted_username}")
        print(f"Hashed password: {hashed_password}")

    except Exception as e:
        logger.error(f"Error registering user: {e}")
        raise

def login_user(username, password): # Removed config parameter
    """Logs in a user, verifying the password."""
    try:
        fernet_key = get_fernet_key() # Get key from KMS or env var

        # Retrieve encrypted_username and hashed_password from the database
        # (replace with your actual database interaction)
        # Example:
        # user_data = database.get_user(username)
        # encrypted_username = user_data["encrypted_username"]
        # stored_hash = user_data["hashed_password"]

        # Simulate retrieval from database (replace with actual database call)
        # This is just for demonstration purposes.  DO NOT HARDCODE CREDENTIALS.
        # NEVER STORE REAL HASHES OR KEYS IN CODE
        encrypted_username = encrypt_data(username, fernet_key) # Replace with database retrieval
        stored_hash = bcrypt.hashpw("SecurePassword123!".encode('utf-8'), bcrypt.gensalt()).decode('utf-8') # Replace with database retrieval

        decrypted_username = decrypt_data(encrypted_username, fernet_key)
        if verify_password(password, stored_hash) and decrypted_username == username:
            print("Login successful!")
            return True
        else:
            print("Login failed.")
            return False

    except Exception as e:
        logger.error(f"Error logging in user: {e}")
        return False

def rotate_fernet_key():
    """
    Rotates the Fernet key.  This is a complex operation and requires careful planning.
    This example uses MultiFernet to allow decryption with the old key while encrypting with the new key.
    In a real-world scenario, you would need to re-encrypt all data with the new key.
    """
    try:
        # 1. Generate a new Fernet key.
        new_key = Fernet.generate_key().decode()

        # 2. Get the old key (from environment variable or KMS).
        old_key = get_fernet_key()

        # 3. Create a MultiFernet instance with the new key as primary and the old key as secondary.
        multi_fernet = MultiFernet([Fernet(new_key.encode()), Fernet(old_key.encode())])

        # 4.  Update the environment variable (or KMS) with the new key.  This is a critical step.
        os.environ["FERNET_KEY"] = new_key

        # 5.  Re-encrypt all data with the new key.  This is a complex and time-consuming process.
        #    This would involve querying the database, decrypting the data with the old key,
        #    and re-encrypting it with the new key.

        # 6.  (After all data has been re-encrypted)  Consider removing the old key from MultiFernet
        #     and eventually destroying the old key.  This requires careful planning and monitoring.

        logger.info("Fernet key rotated successfully.  Remember to re-encrypt all data.")
        return multi_fernet  # Return the MultiFernet instance for use in decryption

    except Exception as e:
        logger.error(f"Error rotating Fernet key: {e}")
        raise

if __name__ == '__main__':
    # Load configuration
    try:
        config = load_config(CONFIG_FILE)
    except Exception as e:
        print(f"Failed to load configuration: {e}")
        exit(1)

    # Example usage
    try:
        # Example: Register a new user
        new_username = "testuser"
        new_password = "SecurePassword123!"
        register_user(new_username, new_password)

        # Example: Log in the user
        login_successful = login_user(new_username, new_password)

        if login_successful:
            log_username(new_username)  # Log a generic user event

        # Example: Rotate the Fernet key
        # rotate_fernet_key() # Commented out for safety - requires careful planning

    except Exception as e:
        print(f"An error occurred during example usage: {e}")

