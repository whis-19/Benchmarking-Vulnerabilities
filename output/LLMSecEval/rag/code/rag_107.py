import os
import stat
import secrets
import hashlib
import json

def generate_salt():
    """Generates a random salt for password hashing."""
    return secrets.token_hex(16)

def hash_password(password, salt):
    """Hashes the password using SHA-256 with a salt."""
    salted_password = salt.encode('utf-8') + password.encode('utf-8')
    hashed_password = hashlib.sha256(salted_password).hexdigest()
    return hashed_password

def store_credentials(username, password, config_file="credentials.json"):
    """Stores credentials securely in a configuration file.

    Args:
        username (str): The username.
        password (str): The password.
        config_file (str): The name of the configuration file.
    """
    salt = generate_salt()
    hashed_password = hash_password(password, salt)

    credentials = {
        "username": username,
        "salt": salt,
        "hashed_password": hashed_password
    }

    try:
        with open(config_file, "w") as f:
            json.dump(credentials, f)

        # Restrict file permissions to owner read-only
        os.chmod(config_file, stat.S_IRUSR)  # Owner read-only
        print(f"Credentials stored securely in {config_file}")

    except Exception as e:
        print(f"Error storing credentials: {e}")

def main():
    """Main function to demonstrate secure credential storage."""
    username = input("Enter username: ")
    password = input("Enter password: ")

    store_credentials(username, password)

if __name__ == "__main__":
    main()

