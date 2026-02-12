import os
import fcntl
import stat
import secrets
import logging
import bcrypt  # pip install bcrypt
import json

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def secure_config_write(config_file_path, sensitive_data):
    """
    Creates or writes to a configuration file with restricted permissions,
    encrypts sensitive data before writing, and ensures proper file closing.

    Args:
        config_file_path (str): The path to the configuration file.
        sensitive_data (dict): A dictionary containing configuration data,
                                 including potentially sensitive information.
    """

    # Input validation: Check file path
    if not isinstance(config_file_path, str):
        raise TypeError("config_file_path must be a string.")
    if not config_file_path:
        raise ValueError("config_file_path cannot be empty.")

    # Input validation: Check sensitive_data
    if not isinstance(sensitive_data, dict):
        raise TypeError("sensitive_data must be a dictionary.")

    # Password Complexity Requirements
    if "password" in sensitive_data:
        password = sensitive_data["password"]
        if not isinstance(password, str):
            raise TypeError("Password must be a string.")

        if len(password) < 8:
            raise ValueError("Password must be at least 8 characters long.")
        if not any(char.isdigit() for char in password):
            raise ValueError("Password must contain at least one digit.")
        if not any(char.isupper() for char in password):
            raise ValueError("Password must contain at least one uppercase letter.")
        if not any(char.islower() for char in password):
            raise ValueError("Password must contain at least one lowercase letter.")

        # Generate a salt and hash the password using bcrypt
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        sensitive_data["password"] = hashed_password.decode('utf-8')  # Store the hash as a string
        # No need to store the salt separately with bcrypt
    elif "password" not in sensitive_data:
        logging.warning("Password key is missing from sensitive_data.  This may be a security risk if a password is required.")


    # Convert the dictionary to JSON format
    try:
        config_string = json.dumps(sensitive_data, indent=4)  # Use indent for readability
    except TypeError as e:
        logging.error(f"Error converting data to JSON: {e}")
        raise

    # File creation and writing with restricted permissions
    try:
        # Use os.open with O_CREAT and specific permissions
        file_descriptor = os.open(config_file_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, stat.S_IRUSR | stat.S_IWUSR)  # Owner read/write only

        # Acquire an exclusive lock to prevent race conditions
        fcntl.flock(file_descriptor, fcntl.LOCK_EX)

        # Write the configuration string to the file
        os.write(file_descriptor, config_string.encode('utf-8'))

        # Release the lock
        fcntl.flock(file_descriptor, fcntl.LOCK_UN)

        logging.info(f"Configuration file successfully written.") #Sanitized log message

    except FileNotFoundError as e:
        logging.error(f"Configuration file not found.") #Sanitized log message
        raise
    except PermissionError as e:
        logging.error(f"Permission error writing to configuration file.") #Sanitized log message
        raise
    except OSError as e:
        logging.error(f"Error writing to configuration file.") #Sanitized log message
        raise  # Re-raise the exception to signal failure

    finally:
        # Ensure the file is always closed
        if 'file_descriptor' in locals(): # Check if file_descriptor is defined
            try:
                os.close(file_descriptor)
            except OSError as e:
                logging.error(f"Error closing file.") #Sanitized log message

# Example Usage:
if __name__ == "__main__":
    # Use a more obscure default location in the user's home directory
    default_config_file = os.path.join(os.path.expanduser("~"), ".config", "myapp", "config.json")
    config_file = os.environ.get("CONFIG_FILE", default_config_file) # Configuration file path from environment variable

    # Create the directory if it doesn't exist
    config_dir = os.path.dirname(config_file)
    if not os.path.exists(config_dir):
        try:
            os.makedirs(config_dir, mode=0o700)  # Owner-only permissions
        except OSError as e:
            print(f"Error creating configuration directory: {e}")
            exit(1)

    sensitive_config_data = {
        "username": "admin",
        "password": "MySecretPassword123",
        "database_url": "localhost:5432",
        "api_key": secrets.token_hex(32),
        "is_admin": True,
        "port": 8080
    }

    try:
        secure_config_write(config_file, sensitive_config_data)
        print(f"Successfully wrote configuration to {config_file}")
    except Exception as e:
        print(f"Failed to write configuration: {e}")

