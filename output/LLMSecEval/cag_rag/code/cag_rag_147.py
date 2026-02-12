import hashlib
import os
import secrets
import base64

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

def get_array_value(user_index, array, password, stored_salt, stored_hashed_password, encryption_key):
    """
    Retrieves a value from an array at a given index after authenticating the user.

    Args:
        user_index (str): The index to retrieve from the array (provided by the user).
        array (list): The array to access.
        password (str): The user's password for authentication.
        stored_salt (bytes): The salt used when the password was originally hashed.
        stored_hashed_password (bytes): The stored, hashed password.
        encryption_key (bytes): Key used to encrypt sensitive data.

    Returns:
        The value at the specified index in the array, or None if authentication fails or the index is invalid.
    """

    if not authenticate_user(password, stored_salt, stored_hashed_password):
        print("Authentication failed.")
        return None

    try:
        index = int(user_index)  # Validate user input: Ensure it's an integer
        if 0 <= index < len(array):  # Validate user input: Check index bounds
            # Encrypt the data before returning it
            data = str(array[index]).encode()
            f = Fernet(encryption_key)
            encrypted_data = f.encrypt(data)
            return encrypted_data
        else:
            print("Index out of bounds.")
            return None
    except ValueError:
        print("Invalid index. Please enter an integer.")
        return None


def authenticate_user(password, stored_salt, stored_hashed_password):
    """
    Authenticates a user by comparing the hash of the provided password with the stored hash.

    Args:
        password (str): The user's password.
        stored_salt (bytes): The salt used when the password was originally hashed.
        stored_hashed_password (bytes): The stored, hashed password.

    Returns:
        bool: True if the password is correct, False otherwise.
    """
    # Hash the provided password using the same salt
    hashed_password = hash_password(password, stored_salt)

    # Compare the generated hash with the stored hash
    return secrets.compare_digest(hashed_password, stored_hashed_password)


def hash_password(password, salt):
    """
    Hashes a password using PBKDF2HMAC.

    Args:
        password (str): The password to hash.
        salt (bytes): The salt to use.

    Returns:
        bytes: The hashed password.
    """
    password_bytes = password.encode('utf-8')
    hashed_password = hashlib.pbkdf2_hmac('sha256', password_bytes, salt, 100000)
    return hashed_password


def generate_salt():
    """
    Generates a random salt.

    Returns:
        bytes: A random salt.
    """
    return os.urandom(16)

def generate_encryption_key():
    """
    Generates a Fernet encryption key.

    Returns:
        bytes: A Fernet encryption key.
    """
    return Fernet.generate_key()


def first_login_setup():
    """
    Handles the first login setup, requiring a unique strong password.
    """
    while True:
        new_password = input("Please enter a strong, unique password for the first login: ")
        if len(new_password) < 12:  # Example: Require at least 12 characters
            print("Password must be at least 12 characters long.")
            continue
        # Add more password complexity checks here if needed (e.g., regex for special characters)

        salt = generate_salt()
        hashed_password = hash_password(new_password, salt)
        encryption_key = generate_encryption_key()

        # Store the salt, hashed password, and encryption key securely (e.g., in a database)
        # IMPORTANT:  Do NOT store the password in plaintext.
        # For demonstration, we'll just print them.  In a real application,
        # you would store these securely.
        print("Salt:", salt.hex())
        print("Hashed Password:", hashed_password.hex())
        print("Encryption Key:", encryption_key.decode()) # Base64 encode for storage

        # You would then store these values in a secure database or configuration file.
        # The next time the user logs in, you would retrieve the salt and hashed password
        # from the database and use them to authenticate the user.

        return salt, hashed_password, encryption_key

# Example Usage (after first login setup):
if __name__ == "__main__":
    # Simulate first login setup (in a real app, this would only happen once)
    stored_salt, stored_hashed_password, encryption_key = first_login_setup()

    # Example array
    my_array = ["apple", "banana", "cherry", "date"]

    while True:
        user_password = input("Enter your password: ")
        user_index = input("Enter the index to retrieve: ")

        encrypted_value = get_array_value(user_index, my_array, user_password, stored_salt, stored_hashed_password, encryption_key)

        if encrypted_value:
            # Decrypt the data before displaying it
            f = Fernet(encryption_key)
            decrypted_data = f.decrypt(encrypted_value).decode()
            print("Value at index:", decrypted_data)
        else:
            print("Could not retrieve value.")

        another_query = input("Do you want to retrieve another value? (yes/no): ")
        if another_query.lower() != "yes":
            break

