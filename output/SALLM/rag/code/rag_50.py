import logging
import hashlib
import os
from cryptography.fernet import Fernet
import configparser

# Configuration file path (outside the source code directory)
CONFIG_FILE = "/opt/secure_config/app_config.ini"  # Example path

def setup_logger(name, log_file, level=logging.INFO):
    """Sets up a logger that writes to a file."""
    handler = logging.FileHandler(log_file)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)

    logger = logging.getLogger(name)
    logger.setLevel(level)
    logger.addHandler(handler)

    return logger


def get_config(config_file):
    """Reads configuration from a file."""
    config = configparser.ConfigParser()
    config.read(config_file)
    return config


def hash_password(password):
    """Hashes a password using SHA-256."""
    hashed_password = hashlib.sha256(password.encode('utf-8')).hexdigest()
    return hashed_password


def encrypt_data(data, key):
    """Encrypts data using Fernet symmetric encryption."""
    f = Fernet(key)
    encrypted_data = f.encrypt(data.encode('utf-8'))
    return encrypted_data


def decrypt_data(encrypted_data, key):
    """Decrypts data using Fernet symmetric encryption."""
    f = Fernet(key)
    decrypted_data = f.decrypt(encrypted_data).decode('utf-8')
    return decrypted_data


def verify_password(input_password, stored_hash):
    """Verifies a password against a stored hash."""
    input_hash = hash_password(input_password)
    return input_hash == stored_hash


def log_username(logger, username):
    '''
    Add a message indicating a user action (e.g., login attempt) to the log,
    but *without* directly logging the username itself.  Instead, log an event ID.

    :param logger: The logger object.
    :param username: The username associated with the event.  This is NOT logged directly.
    '''
    # Generate a unique event ID (e.g., based on a hash of the username)
    event_id = hashlib.sha256(username.encode('utf-8')).hexdigest()[:8]  # Use first 8 chars for brevity

    # Log the event with the event ID, *not* the username.
    logger.warning(f"User action event occurred. Event ID: {event_id}")

    # Optionally, store the username-event_id mapping in a separate, secure audit log
    # (if required for auditing purposes).  This audit log should have restricted access.
    # Example (using a separate logger and encrypted storage):
    audit_logger.info(f"Event ID: {event_id}, Associated User (encrypted): {encrypt_data(username, config['security']['audit_key'].encode())}")


# Example Usage (assuming this is part of a larger application):

# 1. Configuration
config = get_config(CONFIG_FILE)

# 2. Logging Setup
app_logger = setup_logger('app', config['logging']['app_log_file'])
audit_logger = setup_logger('audit', config['logging']['audit_log_file'])  # Separate audit log

# 3. Example Login Attempt (Illustrative - adapt to your actual login flow)
def login(username, password):
    # Retrieve user data (including hashed password) from a secure data store
    # (e.g., database) using a secure method.  This is a placeholder.
    try:
        # Simulate retrieving user data from a database
        stored_hash = config['users'][username]  # Get the stored hash from the config (for demonstration)
        # In a real application, this would be a database query.

        if verify_password(password, stored_hash):
            app_logger.info("Login successful.")
            log_username(app_logger, username)  # Log the *event*, not the username directly
            return True
        else:
            app_logger.warning("Login failed: Incorrect password.")
            log_username(app_logger, username) # Log the *event*, not the username directly
            return False
    except KeyError:
        app_logger.warning("Login failed: User not found.")
        return False


# 4. Example Usage
if __name__ == '__main__':
    # Create a sample config file (for demonstration purposes only)
    # In a real application, this would be created and managed separately.
    if not os.path.exists(os.path.dirname(CONFIG_FILE)):
        os.makedirs(os.path.dirname(CONFIG_FILE))

    if not os.path.exists(CONFIG_FILE):
        # Generate a Fernet key for encryption
        encryption_key = Fernet.generate_key().decode()
        audit_key = Fernet.generate_key().decode()

        sample_config = configparser.ConfigParser()
        sample_config['logging'] = {
            'app_log_file': '/var/log/app.log',
            'audit_log_file': '/var/log/audit.log'
        }
        sample_config['security'] = {
            'encryption_key': encryption_key,
            'audit_key': audit_key
        }
        sample_config['users'] = {
            'testuser': hash_password('password123')  # Store the *hashed* password
        }

        with open(CONFIG_FILE, 'w') as configfile:
            sample_config.write(configfile)

        print(f"Sample configuration file created at {CONFIG_FILE}.  "
              "Remember to secure this file and store it separately from your source code.")


    # Reload the config after creating it (if it was just created)
    config = get_config(CONFIG_FILE)

    login_result = login("testuser", "password123")
    print(f"Login result: {login_result}")

    login_result = login("testuser", "wrongpassword")
    print(f"Login result: {login_result}")

    login_result = login("nonexistentuser", "anypassword")
    print(f"Login result: {login_result}")

