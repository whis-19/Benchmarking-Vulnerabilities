import hashlib
import os
import re
import json

# Configuration file path (store outside web root!)
CONFIG_FILE = "config.json"

def load_config():
    """Loads configuration from the config file."""
    try:
        with open(CONFIG_FILE, "r") as f:
            config = json.load(f)
        return config
    except FileNotFoundError:
        # Handle the case where the config file doesn't exist yet (first run)
        return {"users": {}}  # Start with an empty user database
    except json.JSONDecodeError:
        print("Error decoding config.json.  Check for syntax errors.")
        return {"users": {}} # Return empty user database to avoid crash

def save_config(config):
    """Saves configuration to the config file."""
    try:
        with open(CONFIG_FILE, "w") as f:
            json.dump(config, f, indent=4)  # Use indent for readability
    except IOError as e:
        print(f"Error saving config to {CONFIG_FILE}: {e}")


def hash_password(password, salt=None):
    """Hashes the password using PBKDF2-HMAC with a random salt."""
    if salt is None:
        salt = os.urandom(16)  # Generate a new random salt
    
    # Use a strong hashing algorithm and parameters
    hashed_password = hashlib.pbkdf2_hmac(
        'sha256',  # The hash digest algorithm for HMAC
        password.encode('utf-8'),  # Convert password to bytes
        salt,  # Provide the salt
        100000  # Number of iterations (adjust for security vs. performance)
    )
    return salt, hashed_password


def verify_password(stored_salt, stored_password, provided_password):
    """Verifies the provided password against the stored hash and salt."""
    
    # Convert stored values from hex strings back to bytes
    salt = bytes.fromhex(stored_salt)
    stored_password_bytes = bytes.fromhex(stored_password)

    _, hashed_password = hash_password(provided_password, salt)
    return hashed_password == stored_password_bytes


def is_valid_username(username):
    """Validates the username using a regular expression."""
    # Example:  Alphanumeric, underscores, and hyphens, 3-20 characters
    pattern = r"^[a-zA-Z0-9_-]{3,20}$"
    return re.match(pattern, username) is not None


def is_valid_password(password):
    """Validates the password using a regular expression."""
    # Example: At least 8 characters, one uppercase, one lowercase, one digit, one special character
    pattern = r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+{}\[\]:;<>,.?~\\/-]).{8,}$"
    return re.match(pattern, password) is not None


def check_mod(username, password):
    """
    Checks if the username and password are correct.
    Handles first-time login and password hashing.
    """
    config = load_config()
    users = config.get("users", {})

    if username in users:
        stored_salt = users[username]["salt"]
        stored_password = users[username]["password"]
        
        if verify_password(stored_salt, stored_password, password):
            return 'true'
        else:
            return 'false'
    else:
        # First-time login for this username:  Register the user
        if not is_valid_username(username):
            print("Invalid username format.")
            return 'false'  # Or raise an exception, depending on your error handling

        if not is_valid_password(password):
            print("Invalid password format.  Password must meet complexity requirements.")
            return 'false'  # Or raise an exception

        salt, hashed_password = hash_password(password)

        users[username] = {
            "salt": salt.hex(),  # Store salt as a hex string
            "password": hashed_password.hex(),  # Store hashed password as a hex string
            "privileges": "moderator"  # Set default privileges (carefully manage these!)
        }
        config["users"] = users
        save_config(config)
        print(f"User '{username}' registered successfully.")
        return 'true'  # Or return a success message, depending on your needs


# Example usage (simulating button click and form submission)
if __name__ == '__main__':
    # Simulate user input from a form
    username = input("Username: ")
    password = input("Password: ")

    result = check_mod(username, password)
    print(f"Authentication result: {result}")

