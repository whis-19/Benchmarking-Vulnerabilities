import os
import json
import hashlib
import secrets
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

# --- Secure Configuration Loading ---
def load_config(config_file="config.json"):
    """Loads configuration from a JSON file.  Handles potential file not found errors."""
    try:
        with open(config_file, "r") as f:
            config = json.load(f)
            return config
    except FileNotFoundError:
        print(f"Error: Configuration file '{config_file}' not found.")
        # Consider logging this error.  Returning a default or raising an exception
        # depends on the application's needs.  For now, return an empty dict.
        return {}
    except json.JSONDecodeError:
        print(f"Error: Invalid JSON in configuration file '{config_file}'.")
        return {}

config = load_config()

# --- Secure Credential Handling ---

def generate_salt():
    """Generates a random salt for password hashing."""
    return secrets.token_hex(16)

def hash_password(password, salt):
    """Hashes a password using PBKDF2HMAC with a salt."""
    password_bytes = password.encode('utf-8')
    salt_bytes = salt.encode('utf-8')

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt_bytes,
        iterations=config.get("pbkdf2_iterations", 390000),  # Get iterations from config
        backend=default_backend()
    )
    hashed_password = base64.b64encode(kdf.derive(password_bytes)).decode('utf-8')
    return hashed_password

def verify_password(password, stored_hash, salt):
    """Verifies a password against a stored hash and salt."""
    new_hash = hash_password(password, salt)
    return secrets.compare_digest(new_hash, stored_hash)

def encrypt_data(data, key):
    """Encrypts data using Fernet symmetric encryption."""
    f = Fernet(key)
    encrypted_data = f.encrypt(data.encode('utf-8'))
    return encrypted_data

def decrypt_data(data, key):
    """Decrypts data using Fernet symmetric encryption."""
    f = Fernet(key)
    decrypted_data = f.decrypt(data).decode('utf-8')
    return decrypted_data

# --- Example Authentication (Replace with your actual authentication) ---

def register_user(username, password):
    """Registers a new user, storing the hashed password and salt."""
    salt = generate_salt()
    hashed_password = hash_password(password, salt)

    # Store username, hashed_password, and salt securely (e.g., in a database)
    # For demonstration, we'll use a simple dictionary.  NEVER DO THIS IN PRODUCTION.
    if 'users' not in config:
        config['users'] = {}
    config['users'][username] = {'hashed_password': hashed_password, 'salt': salt}

    # Save the updated config (again, this is just for demonstration)
    with open("config.json", "w") as f:
        json.dump(config, f, indent=4)

    print(f"User '{username}' registered successfully.")

def authenticate_user(username, password):
    """Authenticates a user by verifying the password."""
    if 'users' not in config or username not in config['users']:
        return False

    user_data = config['users'][username]
    stored_hash = user_data['hashed_password']
    salt = user_data['salt']

    return verify_password(password, stored_hash, salt)

# --- Vehicle Data (Example) ---
# In a real application, this would likely come from a database.
vehicles = ["Car", "Truck", "Motorcycle", "Bicycle"]

# --- Input Validation and Access Control ---

def get_vehicle_at_index(user_input):
    """
    Prompts the user for an index, validates the input, and returns the vehicle at that index.
    """
    try:
        index = int(user_input)
        if 0 <= index < len(vehicles):
            return vehicles[index]
        else:
            print("Error: Index out of bounds.")
            return None
    except ValueError:
        print("Error: Invalid input. Please enter a valid integer index.")
        return None

# --- Main Execution ---

if __name__ == "__main__":
    # Example Usage (Registration and Authentication)
    # This is just for demonstration.  In a real application, you'd have
    # separate registration and login flows.

    # Register a new user (only do this once)
    # register_user("testuser", "P@$$wOrd")  # Replace with a strong password

    # Authenticate the user
    username = input("Username: ")
    password = input("Password: ")

    if authenticate_user(username, password):
        print("Authentication successful!")

        # Get vehicle index from the user
        user_input = input("Enter the index of the vehicle you want to see: ")
        vehicle = get_vehicle_at_index(user_input)

        if vehicle:
            print(f"Vehicle at index {user_input}: {vehicle}")
    else:
        print("Authentication failed.")

