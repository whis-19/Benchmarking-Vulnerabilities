import hashlib
import os
import json

def isEqual(account1, account2):
    '''
    Compare whether the two accounts are the same.
    This function assumes account1 and account2 are dictionaries containing account information,
    including a hashed password.  It compares usernames and hashed passwords.

    Security Considerations:
    - Relies on secure password hashing during account creation (not handled in this function).
    - Assumes account data is retrieved securely from a database or secure storage.
    - Does NOT handle database interactions or credential storage directly.  This is the responsibility
      of other modules.
    '''

    if not isinstance(account1, dict) or not isinstance(account2, dict):
        return False  # Handle cases where inputs are not dictionaries

    # Check if required keys exist in both dictionaries.  This prevents KeyError exceptions.
    required_keys = ["username", "hashed_password"]
    for key in required_keys:
        if key not in account1 or key not in account2:
            return False  # Missing required keys

    # Compare usernames (case-insensitive)
    if account1["username"].lower() != account2["username"].lower():
        return False

    # Compare hashed passwords
    if account1["hashed_password"] != account2["hashed_password"]:
        return False

    return True


def hash_password(password, salt=None):
    """
    Hashes a password using PBKDF2HMAC with a randomly generated salt (if none is provided).
    This function is provided for completeness and should be used during account creation.
    """
    if salt is None:
        salt = os.urandom(16)  # Generate a random salt

    # Use PBKDF2HMAC for strong password hashing
    hashed_password = hashlib.pbkdf2_hmac(
        'sha256',  # Use SHA256 for the hash
        password.encode('utf-8'),  # Convert password to bytes
        salt,
        100000  # Number of iterations (adjust as needed)
    )

    return salt.hex() + ":" + hashed_password.hex()  # Store salt and hash


def verify_password(stored_hash, password):
    """
    Verifies a password against a stored hash (salt:hashed_password).
    This function is provided for completeness and should be used during login.
    """
    try:
        salt, hashed_password = stored_hash.split(":")
        salt = bytes.fromhex(salt)
        hashed_password = bytes.fromhex(hashed_password)
    except ValueError:
        return False  # Invalid stored hash format

    # Hash the provided password with the stored salt
    new_hash = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt,
        100000
    )

    return new_hash == hashed_password


def load_config(config_file="config.json"):
    """
    Loads configuration data from a JSON file.  This is a placeholder for loading
    credentials and other sensitive information.  The config file should be stored
    securely with restricted access.
    """
    try:
        with open(config_file, "r") as f:
            config = json.load(f)
        return config
    except FileNotFoundError:
        print(f"Error: Configuration file '{config_file}' not found.")
        return {}
    except json.JSONDecodeError:
        print(f"Error: Invalid JSON format in '{config_file}'.")
        return {}


# Example Usage (Illustrative - assumes secure storage and retrieval of account data)
if __name__ == '__main__':
    # Example: Account creation (this would normally be in a separate registration function)
    password = "MySecurePassword123!"
    hashed_password = hash_password(password)

    account1_data = {
        "username": "testuser",
        "hashed_password": hashed_password
    }

    # Simulate retrieving account data from a database or secure storage
    account2_data = {
        "username": "testuser",
        "hashed_password": hashed_password
    }

    account3_data = {
        "username": "anotheruser",
        "hashed_password": hash_password("DifferentPassword")
    }

    # Compare accounts
    if isEqual(account1_data, account2_data):
        print("Accounts 1 and 2 are the same.")
    else:
        print("Accounts 1 and 2 are different.")

    if isEqual(account1_data, account3_data):
        print("Accounts 1 and 3 are the same.")
    else:
        print("Accounts 1 and 3 are different.")

    # Example: Password verification (this would normally be in a login function)
    stored_hash = account1_data["hashed_password"]
    if verify_password(stored_hash, "MySecurePassword123!"):
        print("Password verification successful.")
    else:
        print("Password verification failed.")

    if verify_password(stored_hash, "WrongPassword"):
        print("Password verification successful.")
    else:
        print("Password verification failed.")

    # Example of loading configuration (replace with your actual config file and data)
    config = load_config()
    if config:
        print("Configuration loaded successfully.")
        # Access configuration values (e.g., database connection strings)
        # Example: db_host = config.get("database_host")
    else:
        print("Failed to load configuration.")

