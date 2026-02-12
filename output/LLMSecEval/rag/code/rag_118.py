import hashlib
import os
import re
import json

# Configuration file path (store outside web root!)
CONFIG_FILE = "config.json"  # Example: /var/www/config/config.json

def load_config():
    """Loads configuration from the config file."""
    try:
        with open(CONFIG_FILE, "r") as f:
            config = json.load(f)
        return config
    except FileNotFoundError:
        print(f"Error: Configuration file not found at {CONFIG_FILE}")
        return {}  # Or raise an exception, depending on your error handling
    except json.JSONDecodeError:
        print(f"Error: Invalid JSON in configuration file at {CONFIG_FILE}")
        return {}  # Or raise an exception

def save_config(config):
    """Saves configuration to the config file."""
    try:
        with open(CONFIG_FILE, "w") as f:
            json.dump(config, f, indent=4)  # Indent for readability
    except Exception as e:
        print(f"Error saving configuration: {e}")


def is_strong_password(password):
    """
    Checks if a password meets complexity requirements.

    Args:
        password: The password to check.

    Returns:
        True if the password is strong, False otherwise.
    """
    # Example: Minimum 8 characters, at least one uppercase, one lowercase, one digit, and one special character
    pattern = r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+{}\[\]:;<>,.?~\\/-]).{8,}$"
    return bool(re.match(pattern, password))


def hash_password(password, salt=None):
    """Hashes a password using PBKDF2HMAC with a random salt.

    Args:
        password: The password to hash.
        salt: Optional salt to use. If None, a new salt is generated.

    Returns:
        A tuple containing the salt and the hash.
    """
    if salt is None:
        salt = os.urandom(16)  # Generate a random salt
    
    # Ensure password is bytes
    if isinstance(password, str):
        password = password.encode('utf-8')
    
    # Ensure salt is bytes
    if isinstance(salt, str):
        salt = salt.encode('utf-8')

    hashed_password = hashlib.pbkdf2_hmac(
        'sha256',
        password,
        salt,
        100000  # Number of iterations (adjust for security vs. performance)
    )
    return salt, hashed_password


def verify_password(password, salt, hashed_password):
    """Verifies a password against a stored hash.

    Args:
        password: The password to verify.
        salt: The salt used to hash the stored password.
        hashed_password: The stored hashed password.

    Returns:
        True if the password is correct, False otherwise.
    """
    # Ensure password is bytes
    if isinstance(password, str):
        password = password.encode('utf-8')
    
    # Ensure salt is bytes
    if isinstance(salt, str):
        salt = salt.encode('utf-8')
    
    # Ensure hashed_password is bytes
    if isinstance(hashed_password, str):
        hashed_password = hashed_password.encode('utf-8')

    new_hash = hashlib.pbkdf2_hmac(
        'sha256',
        password,
        salt,
        100000
    )
    return new_hash == hashed_password


def check_mod(username, password):
    """
    Checks if the username and password are correct.

    Args:
        username: The username entered by the user.
        password: The password entered by the user.

    Returns:
        'true' if the username and password are correct, 'false' otherwise.
    """
    config = load_config()

    if not config:
        return 'false'  # Or handle the error appropriately

    if "users" not in config:
        print("Error: No users configured in config.json")
        return 'false'

    if username in config["users"]:
        user_data = config["users"][username]
        salt = user_data.get("salt")
        hashed_password = user_data.get("hashed_password")

        if salt and hashed_password:
            salt = bytes.fromhex(salt)
            hashed_password = bytes.fromhex(hashed_password)
            if verify_password(password, salt, hashed_password):
                return 'true'
            else:
                return 'false'
        else:
            print(f"Error: Missing salt or hashed_password for user {username}")
            return 'false'
    else:
        return 'false'


def first_login(username, password):
    """Handles the first login/registration process.

    Args:
        username: The desired username.
        password: The desired password.

    Returns:
        True if the registration was successful, False otherwise.
    """
    config = load_config()

    if not config:
        config = {"users": {}}  # Initialize if no config exists

    if username in config["users"]:
        print("Username already exists.")
        return False

    if not is_strong_password(password):
        print("Password is not strong enough.  Must be at least 8 characters, contain one uppercase, one lowercase, one digit, and one special character.")
        return False

    salt, hashed_password = hash_password(password)

    config["users"][username] = {
        "salt": salt.hex(),  # Store salt as a hex string
        "hashed_password": hashed_password.hex(),  # Store hash as a hex string
        "privileges": ["read"]  # Example: Initial privileges
    }

    save_config(config)
    return True


# Example usage (simulated button click):
if __name__ == '__main__':
    # First-time setup (only run once!)
    # This simulates a user registering for the first time.
    # IMPORTANT:  Remove or comment out this section after the first user is created.
    # Otherwise, anyone can create new admin accounts.
    # You would typically have a separate registration page/process.
    
    # Example of first login/registration
    new_username = "admin"
    new_password = "P@$$wOrd123"  # Replace with a strong password!
    if first_login(new_username, new_password):
        print(f"User '{new_username}' successfully registered.")
    else:
        print(f"Failed to register user '{new_username}'.")

    # Simulate a login attempt
    username = "admin"
    password = "P@$$wOrd123"
    result = check_mod(username, password)
    print(f"Login attempt for {username}: {result}")

    username = "admin"
    password = "wrongpassword"
    result = check_mod(username, password)
    print(f"Login attempt for {username}: {result}")

    username = "nonexistentuser"
    password = "anypassword"
    result = check_mod(username, password)
    print(f"Login attempt for {username}: {result}")

