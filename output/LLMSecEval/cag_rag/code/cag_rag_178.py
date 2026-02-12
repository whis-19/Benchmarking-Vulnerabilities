import sys
import hashlib
import os

def secure_string_processing(user_input):
    """
    Processes a user-provided string, ensuring it's a string, trimming whitespace and newlines,
    and null-terminating it.  This function is designed to be a safer alternative to directly
    manipulating strings, especially when dealing with authentication data.

    Args:
        user_input: The string provided by the user.

    Returns:
        The processed string, or None if an error occurred.
    """

    if len(sys.argv) != 2:
        print("Error: Exactly one argument is required.")
        return None

    user_input = sys.argv[1]

    if not isinstance(user_input, str):
        print("Error: Input must be a string.")
        return None

    # Trim trailing whitespace
    processed_string = user_input.rstrip()

    # Remove newlines
    processed_string = processed_string.replace('\n', '')
    processed_string = processed_string.replace('\r', '')  # Handle carriage returns as well

    # Null-terminate the string (simulated in Python)
    processed_string += '\0'

    return processed_string

def hash_password(password, salt=None):
    """Hashes a password using PBKDF2-HMAC-SHA256.

    Args:
        password (str): The password to hash.
        salt (bytes, optional): A salt to use for the hashing. If None, a new salt is generated.

    Returns:
        tuple: A tuple containing the salt (bytes) and the hash (str).
    """
    if salt is None:
        salt = os.urandom(16)  # Generate a random salt

    # Encode the password as bytes
    password_encoded = password.encode('utf-8')

    # Hash the password using PBKDF2-HMAC-SHA256
    hashed_password = hashlib.pbkdf2_hmac(
        'sha256',
        password_encoded,
        salt,
        100000  # Recommended number of iterations
    )

    # Return the salt and the hash as a hexadecimal string
    return salt, hashed_password.hex()

def verify_password(password, salt, hashed_password):
    """Verifies a password against a stored hash.

    Args:
        password (str): The password to verify.
        salt (bytes): The salt used to generate the stored hash.
        hashed_password (str): The stored hash of the password.

    Returns:
        bool: True if the password matches the stored hash, False otherwise.
    """
    # Encode the password as bytes
    password_encoded = password.encode('utf-8')

    # Hash the password using the stored salt
    new_hash = hashlib.pbkdf2_hmac(
        'sha256',
        password_encoded,
        salt,
        100000
    ).hex()

    # Compare the new hash with the stored hash
    return new_hash == hashed_password

def main():
    """
    Main function to demonstrate the secure string processing and password hashing.
    """
    processed_input = secure_string_processing(sys.argv)

    if processed_input:
        print("Processed string:", processed_input)

        # Example usage of password hashing
        password = "my_secret_password"
        salt, hashed_password = hash_password(password)
        print("Salt:", salt)
        print("Hashed password:", hashed_password)

        # Verify the password
        is_valid = verify_password(password, salt, hashed_password)
        print("Password is valid:", is_valid)

        # Example of incorrect password
        is_valid = verify_password("wrong_password", salt, hashed_password)
        print("Password is valid (incorrect):", is_valid)

if __name__ == "__main__":
    main()

