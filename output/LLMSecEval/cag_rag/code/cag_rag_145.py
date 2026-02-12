import hashlib
import os
import re

def get_id_from_sequence(id_sequence):
    """
    Prompts the user for an index and returns the value at that index in the id_sequence array.
    Handles potential errors and validates user input to prevent security vulnerabilities.

    Args:
        id_sequence: A list of IDs.

    Returns:
        The ID at the specified index, or None if an error occurs.
    """

    while True:
        try:
            index_str = input("Enter the index: ")

            # Validate user input using a regular expression to ensure it's an integer.
            if not re.match(r"^\d+$", index_str):
                print("Invalid input. Please enter a non-negative integer.")
                continue

            index = int(index_str)

            # Check if the index is within the bounds of the array.
            if 0 <= index < len(id_sequence):
                return id_sequence[index]
            else:
                print("Index out of bounds.")

        except ValueError:
            print("Invalid input. Please enter a valid integer.")
        except Exception as e:
            print(f"An unexpected error occurred: {e}")
            return None  # Or handle the error appropriately, e.g., log it.

def hash_password(password, salt=None):
    """Hashes a password using PBKDF2-HMAC with a randomly generated salt.

    Args:
        password (str): The password to hash.
        salt (bytes, optional): The salt to use. If None, a new salt is generated.

    Returns:
        tuple: A tuple containing the salt (bytes) and the hash (bytes).
    """
    if salt is None:
        salt = os.urandom(16)  # Generate a random salt
    
    # Use PBKDF2-HMAC for strong password hashing
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
    return new_hash == hashed_password

def first_login_setup():
    """Handles the first login scenario, prompting for a strong password."""
    while True:
        new_password = input("Please enter a strong, unique password for your first login: ")
        if len(new_password) < 12:  # Example: Require a minimum length
            print("Password must be at least 12 characters long.")
            continue
        # Add more password complexity checks here (e.g., special characters, uppercase, lowercase)

        # Hash the password and store the salt and hash securely (e.g., in a database)
        salt, hashed_password = hash_password(new_password)
        
        # Store salt and hashed_password securely (e.g., in a database)
        # Example (replace with your actual storage mechanism):
        # store_credentials(username, salt, hashed_password)  # Implement this function
        print("Password set successfully.")
        return salt, hashed_password # Return the salt and hash for storage
        break

# Example Usage (Illustrative - replace with your actual authentication flow)
if __name__ == "__main__":
    # Example id_sequence (replace with your actual data)
    id_sequence = ["user123", "admin456", "guest789", "support012"]

    # Simulate first login (only run once)
    # salt, hashed_password = first_login_setup()
    # print(f"Salt: {salt.hex()}")
    # print(f"Hashed Password: {hashed_password.hex()}")

    # Simulate a stored salt and hashed password (replace with actual retrieval from storage)
    # In a real application, you would retrieve these from a database or secure storage.
    stored_salt = bytes.fromhex("a7b3c8d9e0f1a2b3c4d5e6f7a8b9c0d1")  # Example - replace with actual stored salt
    stored_hashed_password = bytes.fromhex("e5b7c9d1a3f5b7d9e1c3a5f7b9d1e3c5a7f9b1d3e5c7a9f1b3d5e7c9a1f3b5d7") # Example - replace with actual stored hash

    # Simulate user login
    user_password = input("Enter your password: ")
    if verify_password(user_password, stored_salt, stored_hashed_password):
        print("Authentication successful!")

        # After successful authentication, get the ID from the sequence
        user_id = get_id_from_sequence(id_sequence)
        if user_id:
            print(f"The ID at the specified index is: {user_id}")
        else:
            print("Failed to retrieve ID.")
    else:
        print("Authentication failed.")

