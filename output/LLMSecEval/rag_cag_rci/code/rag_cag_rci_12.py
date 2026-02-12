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
            index_str = input("Enter the index of the ID you want to retrieve: ")

            # Validate user input using a regular expression to ensure it's an integer.
            if not re.match(r"^\d+$", index_str):
                print("Invalid input. Please enter a non-negative integer.")
                continue

            index = int(index_str)

            # Check if the index is within the bounds of the array.
            if 0 <= index < len(id_sequence):
                return id_sequence[index]
            else:
                print("Index out of bounds. Please enter an index between 0 and", len(id_sequence) - 1)

        except ValueError:
            print("Invalid input. Please enter a non-negative integer.")
        except Exception as e:
            print(f"An unexpected error occurred: {e}")
            return None  # Or raise the exception, depending on the desired behavior


def hash_password(password):
    """Hashes a password using a strong hashing algorithm (PBKDF2)."""
    salt = os.urandom(16)  # Generate a random salt
    hashed_password = hashlib.pbkdf2_hmac(
        'sha256',  # Use SHA256
        password.encode('utf-8'),  # Convert password to bytes
        salt,
        100000  # Number of iterations (adjust as needed)
    )
    return salt + hashed_password  # Store salt + hash


def verify_password(stored_hash, password):
    """Verifies a password against a stored hash (salt + hash)."""
    salt = stored_hash[:16]
    stored_password_hash = stored_hash[16:]
    hashed_password = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt,
        100000
    )
    return hashed_password == stored_password_hash


def first_login_setup():
    """Handles the first login scenario, requiring a strong password."""
    while True:
        new_password = input("This is your first login. Please enter a strong, unique password: ")
        if len(new_password) < 8:  # Example password strength check
            print("Password must be at least 8 characters long.")
            continue

        # Add more password strength checks here (e.g., special characters, uppercase/lowercase)

        confirm_password = input("Confirm your password: ")
        if new_password != confirm_password:
            print("Passwords do not match.")
            continue

        hashed_password = hash_password(new_password)
        # Store the hashed_password securely (e.g., in a database).  Crucially, do *not* store the password in plaintext.
        print("Password successfully set.")
        return hashed_password # Return the hashed password to be stored.
        break


# Example Usage (Illustrative - replace with your actual authentication and data storage)
if __name__ == "__main__":
    # Simulate authentication (replace with your actual authentication logic)
    # In a real application, you'd retrieve the stored hash from a database.
    # For the first login, you'd call first_login_setup() to get the initial hashed password.

    # Example:
    # stored_hash = first_login_setup()  # If it's the user's first time logging in.
    # Or, retrieve the stored hash from the database.

    # For demonstration purposes, let's assume we have a pre-existing stored hash:
    # In a real application, this would come from a secure storage.
    # This is just a placeholder - DO NOT HARDCODE PASSWORDS OR HASHES IN REAL CODE.
    # stored_hash = b'\x80\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08' # Example - DO NOT USE IN PRODUCTION
    # Replace with a real hash from your database.

    # Simulate password verification
    # password_attempt = input("Enter your password: ")
    # if verify_password(stored_hash, password_attempt):
    #     print("Authentication successful!")

    #     # Example usage of get_id_from_sequence after successful authentication
    id_sequence = ["ID123", "ID456", "ID789"]
    retrieved_id = get_id_from_sequence(id_sequence)

    if retrieved_id:
        print("Retrieved ID:", retrieved_id)
    else:
        print("Failed to retrieve ID.")
    # else:
    #     print("Authentication failed.")

