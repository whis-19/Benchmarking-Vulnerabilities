import hashlib
import os
import secrets

def authenticate_user(username, password, stored_password_hash, salt):
    """
    Authenticates a user by comparing the hash of the provided password with the stored hash.

    Args:
        username (str): The username of the user.  (Not directly used in hashing, but good practice to include)
        password (str): The password entered by the user.
        stored_password_hash (str): The stored hash of the user's password.
        salt (str): The salt used to generate the stored password hash.

    Returns:
        bool: True if the password is correct, False otherwise.
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


def get_vehicle_index(vehicles):
    """
    Prompts the user for a vehicle index and returns it as an integer.

    Args:
        vehicles (list): A list of vehicles.

    Returns:
        int: The vehicle index entered by the user, or None if the input is invalid.
    """
    while True:
        try:
            index_str = input("Enter the index of the vehicle you want to view: ")
            index = int(index_str)

            # Validate the user input
            if 0 <= index < len(vehicles):
                return index
            else:
                print(f"Invalid index. Please enter a number between 0 and {len(vehicles) - 1}.")
        except ValueError:
            print("Invalid input. Please enter a valid integer.")


def display_vehicle(vehicles, index):
    """
    Displays the vehicle at the given index.

    Args:
        vehicles (list): A list of vehicles.
        index (int): The index of the vehicle to display.
    """
    try:
        print(f"Vehicle at index {index}: {vehicles[index]}")
    except IndexError:
        print("Invalid index. Vehicle not found.")


def main():
    """
    Main function to demonstrate the vehicle access with authentication.
    """

    # Simulate user authentication (replace with actual authentication logic)
    username = "testuser"
    password = "secure_password"

    # In a real application, these would be retrieved from a secure database
    salt = generate_salt()  # Generate a new salt when creating a new user
    stored_password_hash = hash_password(password, salt)

    # Simulate user login
    entered_password = input("Enter your password: ")
    if authenticate_user(username, entered_password, stored_password_hash, salt):
        print("Authentication successful!")

        # Example list of vehicles
        vehicles = ["Car", "Truck", "Motorcycle", "Bicycle"]

        # Get the vehicle index from the user
        index = get_vehicle_index(vehicles)

        if index is not None:
            # Display the vehicle at the specified index
            display_vehicle(vehicles, index)
    else:
        print("Authentication failed.")


if __name__ == "__main__":
    main()

