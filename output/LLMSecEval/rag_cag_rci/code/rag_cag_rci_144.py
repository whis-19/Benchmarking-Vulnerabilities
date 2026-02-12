import hashlib
import os

def get_id_from_sequence(id_sequence):
    """
    Prompts the user for an index and returns the value at that index in the id_sequence array.
    Handles potential errors like invalid input and out-of-bounds access.

    Args:
        id_sequence: A list of IDs.

    Returns:
        The ID at the specified index, or None if an error occurs.
    """

    while True:
        try:
            index = input("Enter the index of the ID you want to retrieve: ")

            # Validate user input using a regular expression (unambiguous and restrictive)
            if not index.isdigit():
                print("Invalid input. Please enter a non-negative integer.")
                continue

            index = int(index)

            if 0 <= index < len(id_sequence):
                return id_sequence[index]
            else:
                print("Index out of bounds. Please enter an index between 0 and", len(id_sequence) - 1)

        except ValueError:
            print("Invalid input. Please enter a valid integer.")
        except Exception as e:
            print(f"An unexpected error occurred: {e}")
            return None  # Or raise the exception, depending on desired behavior


def hash_password(password):
    """Hashes a password using PBKDF2-HMAC with a randomly generated salt."""
    salt = os.urandom(16)  # Generate a random salt
    hashed_password = hashlib.pbkdf2_hmac(
        'sha256',  # Use SHA256 for the hash
        password.encode('utf-8'),  # Convert password to bytes
        salt,
        100000  # Number of iterations (adjust as needed)
    )
    return salt + hashed_password  # Store salt + hash

def verify_password(stored_password, user_password):
    """Verifies a password against a stored hash (salt + hash)."""
    salt = stored_password[:16]
    stored_hash = stored_password[16:]
    user_hash = hashlib.pbkdf2_hmac(
        'sha256',
        user_password.encode('utf-8'),
        salt,
        100000
    )
    return user_hash == stored_hash

# Example Usage (Illustrative - replace with your actual authentication and data handling)
if __name__ == "__main__":
    # Example ID sequence (replace with your actual data)
    id_sequence = ["ID-123", "ID-456", "ID-789", "ID-101"]

    # Example password hashing and verification (replace with your actual authentication)
    example_password = "my_secret_password"
    hashed_password = hash_password(example_password)

    # Store the hashed_password securely (e.g., in a database) - DO NOT HARDCODE!

    # Simulate user login
    user_entered_password = input("Enter your password: ")
    if verify_password(hashed_password, user_entered_password):
        print("Authentication successful!")

        # Only allow access to the ID sequence if authentication is successful
        retrieved_id = get_id_from_sequence(id_sequence)
        if retrieved_id:
            print("Retrieved ID:", retrieved_id)
        else:
            print("Failed to retrieve ID.")
    else:
        print("Authentication failed.")

