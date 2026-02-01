import os
import hashlib
import secrets
import json

# --- Authentication & Authorization ---

def load_credentials(config_file="config.json"):
    """Loads credentials from a configuration file.  Handles potential file not found errors."""
    try:
        with open(config_file, "r") as f:
            config = json.load(f)
            return config.get("users", {})  # Return an empty dict if "users" is not present
    except FileNotFoundError:
        print(f"Error: Configuration file '{config_file}' not found.")
        return {}  # Return an empty dict if the file doesn't exist
    except json.JSONDecodeError:
        print(f"Error: Invalid JSON format in '{config_file}'.")
        return {}  # Return an empty dict if the JSON is invalid
    except Exception as e:
        print(f"Error loading credentials: {e}")
        return {}


def hash_password(password, salt=None):
    """Hashes a password using PBKDF2-HMAC with a randomly generated salt."""
    if salt is None:
        salt = secrets.token_hex(16)  # Generate a random salt
    
    # Encode password and salt to bytes
    password_bytes = password.encode('utf-8')
    salt_bytes = salt.encode('utf-8')

    # Use PBKDF2-HMAC for password hashing
    hashed_password = hashlib.pbkdf2_hmac(
        'sha256',  # Use SHA256 as the hashing algorithm
        password_bytes,
        salt_bytes,
        100000  # Number of iterations (adjust as needed)
    ).hex()
    return salt, hashed_password


def verify_password(password, stored_salt, stored_hash):
    """Verifies a password against a stored hash and salt."""
    # Hash the provided password with the stored salt
    _, hashed_password = hash_password(password, stored_salt)
    
    # Compare the generated hash with the stored hash
    return hashed_password == stored_hash


def register_user(username, password, config_file="config.json"):
    """Registers a new user, hashing the password and storing credentials."""
    users = load_credentials(config_file)
    if username in users:
        print("Username already exists.")
        return False

    salt, hashed_password = hash_password(password)
    users[username] = {"salt": salt, "hash": hashed_password}

    try:
        with open(config_file, "w") as f:
            json.dump({"users": users}, f, indent=4)  # Store the updated user data
        print("User registered successfully.")
        return True
    except Exception as e:
        print(f"Error saving user data: {e}")
        return False


def login(username, password, config_file="config.json"):
    """Authenticates a user."""
    users = load_credentials(config_file)
    user_data = users.get(username)

    if user_data:
        stored_salt = user_data["salt"]
        stored_hash = user_data["hash"]
        if verify_password(password, stored_salt, stored_hash):
            print("Login successful.")
            return True
        else:
            print("Incorrect password.")
            return False
    else:
        print("User not found.")
        return False


# --- Vehicle Access ---

def get_vehicle_at_index(vehicles, index):
    """
    Retrieves and prints a vehicle from a list of vehicles at a given index.
    Handles potential errors gracefully.
    """
    try:
        index = int(index)  # Convert the index to an integer
        if 0 <= index < len(vehicles):
            print(f"Vehicle at index {index}: {vehicles[index]}")
        else:
            print("Error: Index out of bounds.")
    except ValueError:
        print("Error: Invalid index. Please enter an integer.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")


# --- Main Program ---

if __name__ == "__main__":
    # Example usage:

    # 1.  Setup (only needs to be done once)
    # Create a config.json file (or whatever you name it)
    # with the following structure:
    # { "users": {} }
    # This will store user credentials.  Make sure this file is
    # NOT in your source code repository and has restricted access.

    # 2. Register a user (only needs to be done once per user)
    # register_user("testuser", "P@$$wOrd", "config.json")

    # 3. Login
    if login("testuser", "P@$$wOrd", "config.json"):
        # Only proceed if the user is authenticated

        vehicles = ["Car", "Truck", "Motorcycle", "Bicycle"]

        # Get user input for the index
        user_index = input("Enter the index of the vehicle you want to see: ")

        # Access the vehicle at the specified index
        get_vehicle_at_index(vehicles, user_index)
    else:
        print("Authentication failed.  Cannot access vehicle data.")

