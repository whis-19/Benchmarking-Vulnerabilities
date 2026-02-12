import bcrypt
import logging
import os
import json
from cryptography.fernet import Fernet
import getpass  # For secure password input
import secrets  # For generating secure random values
import time  # For timing attack mitigation
import re  # For regular expressions
import validators # For more comprehensive validation

# Configuration file path (store outside the code directory)
CONFIG_FILE = os.environ.get("CONFIG_FILE_PATH", "config.json")  # Example: /var/secrets/config.json

# Encryption key file path (store securely)
KEY_FILE = os.environ.get("KEY_FILE_PATH", "encryption.key")  # Example: /var/secrets/encryption.key

# Configure logging
logging.basicConfig(filename='app.log', level=logging.ERROR, format='%(asctime)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s')

# Reserved usernames
RESERVED_USERNAMES = ["admin", "root", "administrator"]


def generate_key():
    """Generates a new encryption key and saves it to a file."""
    key = Fernet.generate_key()
    try:
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
            # Load the entire config file
            config_data = f.read()
            # Decrypt the entire config file
            key = load_key()
            decrypted_config_data = decrypt(config_data.encode(), key)

            if decrypted_config_data is None:
                logging.error("Failed to decrypt the entire configuration file.")
                return {"users": {}}  # Return an empty config

            config = json.loads(decrypted_config_data)
            logging.info("Configuration loaded and decrypted from file.")
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
    except Exception as e:
        logging.exception(f"Unexpected error loading config: {e}")
        return {"users": {}}


def save_config(config):
    """Saves configuration data to the config file."""
    key = load_key()
    config_str = json.dumps(config, indent=4)
    encrypted_config = encrypt(config_str, key)

    if encrypted_config is None:
        logging.error("Failed to encrypt the entire configuration file.")
        return False  # Indicate failure to save

    try:
        with open(CONFIG_FILE, "wb") as f:  # Write in binary mode
            f.write(encrypted_config)
        os.chmod(CONFIG_FILE, 0o600)  # Restrict permissions
        logging.info("Configuration saved to file.")
        return True # Indicate success
    except OSError as e:
        logging.error(f"Error writing config file: {e}")
        raise  # Re-raise to prevent further execution


def hash_password(password):
    """Hashes a password using bcrypt."""
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    return hashed_password.decode('utf-8')  # Store as string


def verify_password(password, hashed_password):
    """Verifies a password against a stored bcrypt hash, mitigating timing attacks."""
    # Use bcrypt's built-in timing attack resistance
    start_time = time.time()
    result = bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))
    end_time = time.time()
    logging.debug(f"Password verification took {end_time - start_time:.4f} seconds.")
    time.sleep(secrets.randbelow(100) / 1000)  # Add a small, random delay
    return result


def is_valid_email(email):
    """Validates email format using the validators library."""
    return validators.email(email)


def is_strong_password(password):
    """Checks password complexity."""
    if len(password) < 12:
        return False
    if not re.search(r"[a-z]", password):
        return False
    if not re.search(r"[A-Z]", password):
        return False
    if not re.search(r"[0-9]", password):
        return False
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False
    return True


def create_user(username, password, email):
    """Creates a new user account."""
    # Input Sanitization and Validation
    if not (username and password and email):
        print("All fields are required.")
        return False

    if not re.match(r"^[a-zA-Z0-9_]+$", username):
        print("Username must be alphanumeric or contain underscores only.")
        return False

    if len(username) < 3 or len(username) > 20:
        print("Username must be between 3 and 20 characters long.")
        return False

    if username.lower() in RESERVED_USERNAMES:
        print("Username is reserved.")
        return False

    if not is_valid_email(email):
        print("Invalid email address.")
        return False

    if not is_strong_password(password):
        print("Password must be at least 12 characters long and contain a mix of uppercase, lowercase, numbers, and special characters.")
        return False

    config = load_config()
    if username in config["users"]:
        print("Username already exists.")
        return False

    hashed_password = hash_password(password)
    config["users"][username] = {"password": hashed_password, "email": email}  # Store hashed password
    if save_config(config):
        print("User created successfully.")
        logging.info(f"User {username} created successfully.")
        return True
    else:
        print("Failed to save user configuration.")
        return False


def login(username, password):
    """Logs in a user."""
    config = load_config()
    if username not in config["users"]:
        print("Invalid username.")
        logging.warning(f"Login attempt with invalid username: {username}")
        time.sleep(secrets.randbelow(100) / 1000)  # Add a small, random delay
        return False

    user_data = config["users"][username]

    if not verify_password(password, user_data["password"]):
        print("Invalid password.")
        # Introduce a small delay to further mitigate timing attacks
        time.sleep(secrets.randbelow(100) / 1000)  # Sleep for 0-99 milliseconds
        logging.warning(f"Login attempt with invalid password for user: {username}")
        return False

    print("Login successful.")
    logging.info(f"User {username} logged in successfully.")
    return True


def change_email(username, old_email, password, new_email):
    """Changes a user's email address."""
    # Input Sanitization (Basic example - expand as needed)
    if not (old_email and new_email and password):
        print("All fields are required.")
        return False

    if not is_valid_email(new_email):
        print("Invalid new email address.")
        return False

    config = load_config()
    if username not in config["users"]:
        print("Invalid username.")
        logging.warning(f"Change email attempt for invalid username: {username}")
        return False

    user_data = config["users"][username]

    # Verify old email and password
    if user_data["email"] != old_email:
        print("Incorrect old email.")
        logging.warning(f"Incorrect old email provided for user {username}.")
        return False

    if not verify_password(password, user_data["password"]):
        print("Incorrect password.")
        logging.warning(f"Incorrect password provided for user {username} during email change.")
        return False

    # Update email
    config["users"][username]["email"] = new_email
    if save_config(config):
        print("Email changed successfully.")
        logging.info(f"Email changed successfully for user {username}.")
        return True
    else:
        print("Failed to save user configuration.")
        return False


def first_login_setup():
    """Handles the first login setup, requiring a strong password."""
    config = load_config()
    if not config["users"]:  # Check if any users exist
        print("First login detected. Please create an administrator account.")
        while True:
            username = input("Enter a username for the administrator: ")
            # Input Sanitization (Basic example - expand as needed)
            if not re.match(r"^[a-zA-Z0-9_]+$", username):
                print("Invalid username. Must be alphanumeric or contain underscores only.")
                continue

            if len(username) < 3 or len(username) > 20:
                print("Username must be between 3 and 20 characters long.")
                continue

            if username.lower() in RESERVED_USERNAMES:
                print("Username is reserved.")
                continue

            if username in config["users"]:
                print("Username already exists. Please choose a different one.")
                continue

            while True:
                password = getpass.getpass("Enter a strong password for the administrator: ")
                confirm_password = getpass.getpass("Confirm password: ")
                if password != confirm_password:
                    print("Passwords do not match. Please try again.")
                elif not is_strong_password(password):  # Enforce a strong password
                    print("Password must be at least 12 characters long and contain a mix of uppercase, lowercase, numbers, and special characters.")
                else:
                    break

            email = input("Enter an email address for the administrator: ")
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

