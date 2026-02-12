import os
import hashlib
import secrets

def getHash(password):
    '''
    Create a hash of the password with a salt using PBKDF2-HMAC-SHA256.

    Args:
        password (str): The password to hash.

    Returns:
        str: A string containing the salt and the hash, separated by a colon.
             Format: "salt:hash"
    '''

    # Generate a random salt.  Using secrets.token_bytes is preferred for security.
    salt = secrets.token_bytes(16)  # 16 bytes = 128 bits

    # Derive the key using PBKDF2-HMAC-SHA256.
    # - password.encode('utf-8'):  Encode the password to bytes.  Crucial for consistent hashing.
    # - salt: The salt.
    # - iterations:  Number of iterations.  Higher is better, but slower.  100000 is a good starting point.  Adjust based on performance.
    # - dklen:  Desired key length (hash length).  32 bytes (256 bits) is a common choice for SHA256.
    iterations = 100000
    dklen = 32
    hashed_password = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, iterations, dklen)

    # Encode the salt and hash to hexadecimal strings for storage.
    salt_hex = salt.hex()
    hashed_password_hex = hashed_password.hex()

    # Return the salt and hash, separated by a colon.  This format makes it easy to split later.
    return f"{salt_hex}:{hashed_password_hex}"


def verifyPassword(password, stored_value):
    '''
    Verifies a password against a stored hash (salt:hash).

    Args:
        password (str): The password to verify.
        stored_value (str): The stored salt and hash (salt:hash).

    Returns:
        bool: True if the password matches the stored hash, False otherwise.
    '''

    try:
        salt_hex, hashed_password_hex = stored_value.split(":")
        salt = bytes.fromhex(salt_hex)
        stored_hash = bytes.fromhex(hashed_password_hex)
    except ValueError:
        # Handle cases where the stored value is malformed.  Important for security.
        return False  # Or raise an exception, depending on your error handling strategy

    iterations = 100000
    dklen = 32

    # Hash the provided password using the stored salt and parameters.
    hashed_password = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, iterations, dklen)

    # Compare the generated hash with the stored hash.  Use secrets.compare_digest for security.
    return secrets.compare_digest(hashed_password, stored_hash)


if __name__ == '__main__':
    # Example usage:
    password = "my_secret_password"

    # Hash the password
    hashed_value = getHash(password)
    print(f"Hashed password: {hashed_value}")

    # Verify the password
    is_valid = verifyPassword(password, hashed_value)
    print(f"Password is valid: {is_valid}")

    # Test with an incorrect password
    is_valid = verifyPassword("wrong_password", hashed_value)
    print(f"Password is valid (wrong password): {is_valid}")

    # Test with a malformed stored value
    is_valid = verifyPassword("some_password", "invalid_format")
    print(f"Password is valid (invalid format): {is_valid}")

