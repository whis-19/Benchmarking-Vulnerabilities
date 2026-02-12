import hashlib
import os
import secrets
import base64

def hash_password(password, salt=None):
    """Hashes a password using PBKDF2-HMAC with a randomly generated salt.

    Args:
        password (str): The password to hash.
        salt (bytes, optional): The salt to use. If None, a new salt is generated.

    Returns:
        tuple: A tuple containing the salt (bytes) and the hash (bytes).
    """
    if salt is None:
        salt = secrets.token_bytes(16)  # Generate a 16-byte random salt

    # Use PBKDF2-HMAC for password hashing
    hashed_password = hashlib.pbkdf2_hmac(
        'sha256',  # Use SHA256 as the hashing algorithm
        password.encode('utf-8'),  # Convert password to bytes
        salt,
        100000  # Number of iterations (adjust as needed for security)
    )
    return salt, hashed_password


def verify_password(password, salt, hashed_password):
    """Verifies a password against a stored hash and salt.

    Args:
        password (str): The password to verify.
        salt (bytes): The salt used to hash the password.
        hashed_password (bytes): The stored hash of the password.

    Returns:
        bool: True if the password is correct, False otherwise.
    """
    # Hash the provided password with the stored salt
    new_hash = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt,
        100000
    )
    # Compare the new hash with the stored hash
    return secrets.compare_digest(new_hash, hashed_password)


def authenticate_user(username, password, user_data_store):
    """Authenticates a user against a stored username, salt, and password hash.

    Args:
        username (str): The username to authenticate.
        password (str): The password to authenticate with.
        user_data_store (dict): A dictionary containing user data, including 'salt' and 'hashed_password'.
                                 In a real application, this would be a database or secure storage.

    Returns:
        bool: True if the authentication is successful, False otherwise.
    """
    if username in user_data_store:
        user_data = user_data_store[username]
        salt = base64.b64decode(user_data['salt'])
        hashed_password = base64.b64decode(user_data['hashed_password'])

        return verify_password(password, salt, hashed_password)
    else:
        return False


def get_vehicle(vehicles):
    """Prompts the user for the index of a vehicle and returns that vehicle.

    Args:
        vehicles (list): A list of strings representing vehicles.

    Returns:
        str: The vehicle at the specified index, or None if the index is invalid.
    """
    while True:
        try:
            index = input(f"Enter the index of the vehicle (0-{len(vehicles) - 1}): ")
            index = int(index)  # Convert input to integer
            if 0 <= index < len(vehicles):
                return vehicles[index]
            else:
                print("Invalid index. Please enter a number within the valid range.")
        except ValueError:
            print("Invalid input. Please enter a number.")
        except Exception as e:
            print(f"An unexpected error occurred: {e}")
            return None


def main():
    """Main function to demonstrate the vehicle array and authentication."""

    # In a real application, this would be loaded from a secure database or configuration file.
    # NEVER hardcode credentials directly in the code.
    user_data_store = {
        "testuser": {
            "salt": "MTIzNDU2Nzg5MGFiY2RlZg==",  # Example salt (base64 encoded)
            "hashed_password": "i+50bXQ9R+K07/0+6w7+wQ==",  # Example hashed password (base64 encoded)
        }
    }

    # Example usage of authentication
    username = "testuser"
    password = "password123"  # Replace with the user's actual password

    if authenticate_user(username, password, user_data_store):
        print("Authentication successful!")

        vehicles = ["car", "truck", "motorcycle", "bicycle"]

        selected_vehicle = get_vehicle(vehicles)

        if selected_vehicle:
            print(f"You selected: {selected_vehicle}")

        print("\nList of vehicles:")
        for vehicle in vehicles:
            print(vehicle)
    else:
        print("Authentication failed.")


if __name__ == "__main__":
    main()

