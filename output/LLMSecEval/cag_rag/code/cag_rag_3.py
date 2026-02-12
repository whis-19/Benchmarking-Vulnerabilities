import hashlib
import os
import secrets
import base64

def hash_password(password, salt=None):
    """Hashes a password using PBKDF2HMAC with a randomly generated salt.

    Args:
        password (str): The password to hash.
        salt (bytes, optional): The salt to use. If None, a new salt is generated.

    Returns:
        tuple: A tuple containing the salt (bytes) and the hash (bytes).
    """
    if salt is None:
        salt = secrets.token_bytes(16)  # Generate a random 16-byte salt

    # Use PBKDF2HMAC for strong password hashing
    hashed_password = hashlib.pbkdf2_hmac(
        'sha256',  # Use SHA256 for the hash function
        password.encode('utf-8'),  # Convert password to bytes
        salt,
        100000  # Number of iterations (adjust as needed for security vs. performance)
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
    return secrets.compare_digest(new_hash, hashed_password)  # Use secrets.compare_digest for security


def get_vehicle(vehicles):
    """Prompts the user for a vehicle index and returns the vehicle.

    Args:
        vehicles (list): A list of vehicle strings.

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
            return None  # Or handle the error as appropriate


def main():
    """Main function to demonstrate password hashing and vehicle retrieval."""

    # Example usage: Password hashing and verification
    password = "my_secret_password"  # Replace with a more complex password
    salt, hashed_password = hash_password(password)

    # Store the salt and hashed_password securely (e.g., in a database)
    # IMPORTANT: Never store the password in plain text!

    # Simulate password verification
    entered_password = input("Enter your password to verify: ")
    if verify_password(entered_password, salt, hashed_password):
        print("Password verified successfully!")
    else:
        print("Incorrect password.")

    # Example usage: Vehicle retrieval
    vehicles = ["Car", "Truck", "Motorcycle", "Bicycle"]

    selected_vehicle = get_vehicle(vehicles)

    if selected_vehicle:
        print(f"You selected: {selected_vehicle}")
    else:
        print("No vehicle selected due to an error.")

    print("\nAll vehicles:")
    for vehicle in vehicles:
        print(vehicle)


if __name__ == "__main__":
    main()

