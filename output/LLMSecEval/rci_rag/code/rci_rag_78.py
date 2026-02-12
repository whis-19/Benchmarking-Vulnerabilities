import bcrypt
import logging
import os
import json
from cryptography.fernet import Fernet
import getpass  # For secure password input
import secrets  # For generating secure random values
import time  # For timing attack mitigation
import re  # For email validation
import bleach # For sanitizing HTML input
import cerberus # For data validation

# Configuration file path (store outside the code directory)
CONFIG_FILE = os.environ.get("CONFIG_FILE", "config.json")  # Use environment variable, default to "config.json"

# Encryption key file path (store securely)
KEY_FILE = os.environ.get("KEY_FILE", "encryption.key")  # Use environment variable, default to "encryption.key"

# Configure logging
logging.basicConfig(filename='app.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s')

# Email validation regex (more robust)
EMAIL_REGEX = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:\.[a-zA-Z]{2,})?$"

# Define a schema for user data validation
user_schema = {
    'username': {'type': 'string', 'minlength': 3, 'maxlength': 50, 'regex': '^[a-zA-Z0-9_]+$'},
    'password': {'type': 'string', 'minlength': 12, 'regex': '^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*(),.?":{}|<>]).+$'},
    'email': {'type': 'string', 'regex': EMAIL_REGEX}
}

def generate_key():
    """Generates a new encryption key and saves it to a file."""
    key = Fernet.generate_key()
    try:
        os.makedirs(os.path.dirname(KEY_FILE), exist_ok=True) # Ensure directory exists
        with open(KEY_FILE, "wb") as key_file:
            key_file.write(key)
        os.chmod(KEY_FILE, 0o600)  # Restrict permissions
        logging.info("New encryption key generated and saved.")
    except OSError as e:
        logging.error(f"Error writing key file: {e}")
        raise  # Re-raise to prevent further execution
    return key


def load_key():
    """Loads the encryption key from the key file."""
    try:
        with open(KEY_FILE, "rb") as key_file:
            key = key_file.read()
            logging.info("Encryption key loaded from file.")
            return key
    except FileNotFoundError:
        logging.warning("Encryption key not found. Generating a new one.")
        return generate_key()
    except OSError as e:
        logging.error(f"Error reading key file: {e}")
        raise  # Re-raise to prevent further execution


def encrypt(data: str, key: bytes) -> bytes:
    """Encrypts data using Fernet encryption."""
    f = Fernet(key)
    try:
        encrypted_data = f.encrypt(data.encode())
        logging.debug("Data encrypted successfully.")
        return encrypted_data
    except Exception as e:
        logging.error(f"Encryption error: {e}")
        return None


def decrypt(data: bytes, key: bytes) -> str:
    """Decrypts data using Fernet encryption."""
    f = Fernet(key)
    try:
        decrypted_data = f.decrypt(data).decode()
        logging.debug("Data decrypted successfully.")
        return decrypted_data
    except ValueError as e:
        logging.error(f"Decryption error (ValueError): {e}")
        return None
    except Exception as e:
        logging.exception(f"Unexpected decryption error: {e}")
        return None


def load_config():
    """Loads configuration data from the config file."""
    try:
        with open(CONFIG_FILE, "r") as f:
            config = json.load(f)
            logging.info("Configuration loaded from file.")
            # Decrypt sensitive data only when needed
            key = load_key()
            if 'users' in config:
                for username, user_data in config['users'].items():
                    if 'password' in user_data:
                        try:
                            user_data['password'] = decrypt(bytes.fromhex(user_data['password']), key)
                        except Exception as e:
                            logging.error(f"Error decrypting password for user {username}: {e}")
                            user_data['password'] = None  # Handle decryption failure
                    if 'email' in user_data:
                        try:
                            user_data['email'] = decrypt(bytes.fromhex(user_data['email']), key)
                        except Exception as e:
                            logging.error(f"Error decrypting email for user {username}: {e}")
                            user_data['email'] = None  # Handle decryption failure
            return config
    except FileNotFoundError:
        logging.warning("Configuration file not found.  Starting with an empty configuration.")
        return {"users": {}}
    except json.JSONDecodeError:
        logging.error("Error decoding configuration file.  Starting with an empty configuration.")
        return {"users": {}}
    except OSError as e:
        logging.error(f"Error reading config file: {e}")
        return {"users": {}}


def save_config(config):
    """Saves configuration data to the config file."""
    # Encrypt sensitive data before saving
    key = load_key()
    config_copy = config.copy()  # Avoid modifying the original config
    if 'users' in config_copy:
        for username, user_data in config_copy['users'].items():
            if 'password' in user_data:
                try:
                    user_data['password'] = encrypt(user_data['password'], key).hex()
                except Exception as e:
                    logging.error(f"Error encrypting password for user {username}: {e}")
                    user_data['password'] = None  # Handle encryption failure
            if 'email' in user_data:
                try:
                    user_data['email'] = encrypt(user_data['email'], key).hex()
                except Exception as e:
                    logging.error(f"Error encrypting email for user {username}: {e}")
                    user_data['email'] = None  # Handle encryption failure

    try:
        os.makedirs(os.path.dirname(CONFIG_FILE), exist_ok=True) # Ensure directory exists
        with open(CONFIG_FILE, "w") as f:
            json.dump(config_copy, f, indent=4)
        os.chmod(CONFIG_FILE, 0o600)  # Restrict permissions
        logging.info("Configuration saved to file.")
    except OSError as e:
        logging.error(f"Error writing config file: {e}")
        raise  # Re-raise to prevent further execution


def hash_password(password):
    """Hashes a password using bcrypt."""
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(rounds=12))
    return hashed_password.decode('utf-8')  # Store as string


def verify_password(password, hashed_password):
    """Verifies a password against a stored bcrypt hash, mitigating timing attacks."""
    start_time = time.time()
    result = bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))
    end_time = time.time()
    logging.debug(f"Password verification took {end_time - start_time:.4f} seconds.")
    return result


def is_valid_email(email):
    """Validates an email address using a regular expression."""
    return re.match(EMAIL_REGEX, email) is not None

def validate_user_data(data):
    """Validates user data against the schema."""
    v = cerberus.Validator(user_schema)
    if not v.validate(data):
        logging.warning(f"User data validation failed: {v.errors}")
        return False, v.errors
    return True, None

def create_user(username, password, email):
    """Creates a new user account."""

    # Data Validation using Cerberus
    user_data = {'username': username, 'password': password, 'email': email}
    is_valid, errors = validate_user_data(user_data)
    if not is_valid:
        print("Invalid user data:")
        for field, error_list in errors.items():
            for error in error_list:
                print(f"- {field}: {error}")
        return False

    config = load_config()
    if username in config["users"]:
        print("Username already exists.")
        return False

    hashed_password = hash_password(password)
    config["users"][username] = {"password": hashed_password, "email": email}  # Store hashed password
    save_config(config)
    print("User created successfully.")
    logging.info(f"User {username} created successfully.")
    return True


def login(username, password):
    """Logs in a user."""
    config = load_config()
    if username not in config["users"]:
        print("Invalid username.")
        logging.warning(f"Login attempt with invalid username: {username}")
        return False

    user_data = config["users"][username]
    if user_data["password"] is None:
        print("Account is corrupted. Please contact administrator.")
        logging.error(f"Account for user {username} is corrupted (password decryption failed).")
        return False

    if verify_password(password, user_data["password"]):
        print("Login successful.")
        logging.info(f"User {username} logged in successfully.")
        return True
    else:
        print("Invalid password.")
        logging.warning(f"Login attempt with invalid password for user: {username}")
        time.sleep(secrets.randbelow(100) / 1000)
        return False


def change_email(username, old_email, password, new_email):
    """Changes a user's email address."""

    # Validate new email using Cerberus
    is_valid, errors = validate_user_data({'username': username, 'password': password, 'email': new_email}) # Dummy username and password for validation
    if not is_valid or 'email' in errors:
        print("Invalid new email address:")
        if 'email' in errors:
            for error in errors['email']:
                print(f"- email: {error}")
        return False

    config = load_config()
    if username not in config["users"]:
        print("Invalid username.")
        logging.warning(f"Change email attempt for invalid username: {username}")
        return False

    user_data = config["users"][username]

    if user_data["email"] is None:
        print("Account is corrupted. Please contact administrator.")
        logging.error(f"Account for user {username} is corrupted (email decryption failed).")
        return False

    # Verify old email and password
    key = load_key()
    decrypted_email = user_data["email"]  # Email is already decrypted in load_config
    if decrypted_email != old_email:
        print("Incorrect old email.")
        logging.warning(f"Incorrect old email provided for user {username}.")
        return False

    if not verify_password(password, user_data["password"]):
        print("Incorrect password.")
        logging.warning(f"Incorrect password provided for user {username} during email change.")
        return False

    # Update email
    config["users"][username]["email"] = new_email
    save_config(config)
    print("Email changed successfully.")
    logging.info(f"Email changed successfully for user {username}.")
    return True


def first_login_setup():
    """Handles the first login setup, requiring a strong password."""
    config = load_config()
    if not config["users"]:  # Check if any users exist
        print("First login detected. Please create an administrator account.")
        while True:
            username = input("Enter a username for the administrator: ")
            password = getpass.getpass("Enter a strong password for the administrator: ")
            confirm_password = getpass.getpass("Confirm password: ")
            email = input("Enter an email address for the administrator: ")

            if password != confirm_password:
                print("Passwords do not match. Please try again.")
                continue

            if create_user(username, password, email):
                print("Administrator account created successfully.")
                return
            else:
                print("Failed to create administrator account. Please try again.")
    else:
        print("Not the first login. Proceeding with normal login.")


if __name__ == "__main__":
    # Ensure the configuration directory exists
    config_dir = os.path.dirname(os.path.abspath(CONFIG_FILE))
    if not os.path.exists(config_dir):
        os.makedirs(config_dir)
        logging.info(f"Configuration directory created: {config_dir}")

    key_dir = os.path.dirname(os.path.abspath(KEY_FILE))
    if not os.path.exists(key_dir):
        os.makedirs(key_dir)
        logging.info(f"Key directory created: {key_dir}")

    first_login_setup()

    logged_in_user = None  # Initialize logged_in_user outside the loop

    while True:
        print("\nOptions:")
        print("1. Login")
        print("2. Change Email")
        print("3. Exit")

        choice = input("Enter your choice: ")

        if choice == "1":
            username = input("Username: ")
            password = getpass.getpass("Password: ")  # Secure password input
            if login(username, password):
                logged_in_user = username  # Store the logged-in user
            else:
                logged_in_user = None  # Reset if login fails

        elif choice == "2":
            if logged_in_user:
                old_email = input("Old Email: ")
                password = getpass.getpass("Password: ")
                new_email = input("New Email: ")
                change_email(logged_in_user, old_email, password, new_email)
            else:
                print("You must log in first.")

        elif choice == "3":
            break

        else:
            print("Invalid choice.")

