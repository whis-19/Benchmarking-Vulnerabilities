import hashlib
import os
import secrets

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
            index = input("Enter the index of the ID you want to retrieve: ")
            index = int(index)  # Convert input to integer

            if 0 <= index < len(id_sequence):
                return id_sequence[index]
            else:
                print("Error: Index out of bounds. Please enter a valid index.")
        except ValueError:
            print("Error: Invalid input. Please enter an integer.")
        except Exception as e:
            print(f"An unexpected error occurred: {e}")
            return None  # Or handle the error appropriately


def hash_password(password, salt=None):
    """Hashes a password using PBKDF2-HMAC with a randomly generated salt."""
    if salt is None:
        salt = secrets.token_hex(16)  # Generate a random salt
    
    # Encode password and salt to bytes
    password_encoded = password.encode('utf-8')
    salt_encoded = salt.encode('utf-8')

    # Hash the password using PBKDF2-HMAC
    hashed_password = hashlib.pbkdf2_hmac(
        'sha256',  # Use SHA256 for hashing
        password_encoded,
        salt_encoded,
        100000  # Number of iterations (adjust as needed)
    )

    return salt, hashed_password.hex()  # Return salt and hashed password


def verify_password(password, stored_salt, stored_hash):
    """Verifies a password against a stored hash and salt."""
    # Encode password and salt to bytes
    password_encoded = password.encode('utf-8')
    stored_salt_encoded = stored_salt.encode('utf-8')

    # Hash the password using the stored salt
    hashed_password = hashlib.pbkdf2_hmac(
        'sha256',  # Use SHA256 for hashing
        password_encoded,
        stored_salt_encoded,
        100000  # Number of iterations (must match the hashing function)
    )

    return hashed_password.hex() == stored_hash


def generate_api_key():
    """Generates a secure API key."""
    return secrets.token_urlsafe(32)  # 32 bytes is a good length


def encrypt_data(data, key):
    """
    Encrypts data using a symmetric encryption algorithm (AES).
    Note: This is a placeholder.  For real encryption, use a proper library like cryptography.
    """
    # In a real application, use a library like 'cryptography' for AES encryption.
    # This is a simplified example and is NOT secure for production use.
    encrypted_data = "".join([chr(ord(c) + key) for c in data])
    return encrypted_data


def decrypt_data(encrypted_data, key):
    """
    Decrypts data using a symmetric encryption algorithm (AES).
    Note: This is a placeholder.  For real decryption, use a proper library like cryptography.
    """
    # In a real application, use a library like 'cryptography' for AES decryption.
    # This is a simplified example and is NOT secure for production use.
    decrypted_data = "".join([chr(ord(c) - key) for c in encrypted_data])
    return decrypted_data


# Example Usage (Illustrative - replace with secure storage and handling)
if __name__ == "__main__":
    # Example ID sequence
    id_sequence = ["user123", "admin456", "guest789"]

    # Get ID from sequence
    retrieved_id = get_id_from_sequence(id_sequence)

    if retrieved_id:
        print(f"The ID at the specified index is: {retrieved_id}")

    # Example password hashing
    password = "my_secret_password"
    salt, hashed_password = hash_password(password)
    print(f"Salt: {salt}")
    print(f"Hashed password: {hashed_password}")

    # Example password verification
    is_valid = verify_password(password, salt, hashed_password)
    print(f"Password is valid: {is_valid}")

    # Example API key generation
    api_key = generate_api_key()
    print(f"Generated API key: {api_key}")

    # Example data encryption (replace with secure encryption)
    data = "sensitive data"
    encryption_key = 5  # Replace with a strong, randomly generated key
    encrypted_data = encrypt_data(data, encryption_key)
    print(f"Encrypted data: {encrypted_data}")
    decrypted_data = decrypt_data(encrypted_data, encryption_key)
    print(f"Decrypted data: {decrypted_data}")

