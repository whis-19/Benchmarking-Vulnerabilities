import hashlib
import os
import secrets

def authenticate_user(username, password, stored_password_hash, salt):
    """
    Authenticates a user by comparing the hash of the provided password with the stored hash.

    Args:
        username (str): The username of the user.  (Not directly used in hashing, but good practice to include)
        password (str): The password provided by the user.
        stored_password_hash (str): The stored hash of the user's password.
        salt (str): The salt used to generate the stored password hash.

    Returns:
        bool: True if the authentication is successful, False otherwise.
    """
    # Hash the provided password using the same salt
    hashed_password = hash_password(password, salt)

    # Compare the generated hash with the stored hash
    return secrets.compare_digest(hashed_password, stored_password_hash)


def hash_password(password, salt):
    """
    Hashes a password using PBKDF2HMAC with a randomly generated salt.

    Args:
        password (str): The password to hash.
        salt (str): The salt to use for hashing.

    Returns:
        str: The hexadecimal representation of the hashed password.
    """
    # Use PBKDF2HMAC for strong password hashing
    hashed_password = hashlib.pbkdf2_hmac(
        'sha256',  # Use SHA256 for the hash function
        password.encode('utf-8'),  # Convert password to bytes
        salt.encode('utf-8'),  # Use the salt
        100000  # Number of iterations (adjust as needed)
    )
    return hashed_password.hex()


def generate_salt():
    """
    Generates a random salt for password hashing.

    Returns:
        str: A randomly generated salt.
    """
    return secrets.token_hex(16)  # 16 bytes = 32 characters


def get_vehicle_at_index(vehicles):
    """
    Prompts the user for a vehicle index, validates the input, and prints the vehicle at that index.

    Args:
        vehicles (list): A list of vehicles.
    """
    while True:
        try:
            index_str = input("Enter the index of the vehicle you want to view: ")

            # Validate the user input using a regular expression
            if not index_str.isdigit():
                print("Invalid input. Please enter a non-negative integer.")
                continue

            index = int(index_str)

            if 0 <= index < len(vehicles):
                print("Vehicle at index", index, ":", vehicles[index])
                break  # Exit the loop after successful access
            else:
                print("Index out of bounds. Please enter an index between 0 and", len(vehicles) - 1)

        except ValueError:
            print("Invalid input. Please enter a valid integer.")
        except Exception as e:
            print(f"An unexpected error occurred: {e}")


# Example Usage (Illustrative - Replace with secure storage and retrieval)
if __name__ == "__main__":
    # Simulate user registration (in a real application, store these securely)
    username = "testuser"
    password = "secure_password123"
    salt = generate_salt()
    hashed_password = hash_password(password, salt)

    print(f"Simulated user registered with username: {username}")
    print(f"Salt: {salt}")  # Store this securely with the user's record
    print(f"Hashed password: {hashed_password}")  # Store this securely with the user's record

    # Simulate user login
    login_username = "testuser"
    login_password = "secure_password123"  # Correct password
    # Retrieve stored_password_hash and salt from secure storage (e.g., database)
    stored_password_hash = hashed_password
    stored_salt = salt

    if authenticate_user(login_username, login_password, stored_password_hash, stored_salt):
        print("Authentication successful!")

        # Example vehicle list
        vehicles = ["Car", "Truck", "Motorcycle", "Bicycle"]
        get_vehicle_at_index(vehicles)
    else:
        print("Authentication failed.")

