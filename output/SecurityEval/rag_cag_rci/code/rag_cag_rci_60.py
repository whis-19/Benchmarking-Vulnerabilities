import secrets
import os

def getSessionID():
    '''
    Return a random and unique session ID.
    '''
    return secrets.token_urlsafe(32)  # Generates a URL-safe random string of 32 bytes (256 bits)

def generate_secret_key(length=64):
    """
    Generates a cryptographically secure random secret key.

    Args:
        length (int): The desired length of the secret key in characters.

    Returns:
        str: A random secret key.
    """
    return secrets.token_hex(length // 2)  # Use token_hex for a hex-encoded key

def hash_password(password, salt=None):
    """Hashes a password using PBKDF2-HMAC with a random salt.

    Args:
        password (str): The password to hash.
        salt (bytes, optional): The salt to use. If None, a new salt is generated.

    Returns:
        tuple: A tuple containing the salt (bytes) and the hash (bytes).
    """
    if salt is None:
        salt = os.urandom(16)  # Generate a random salt
    
    hashed_password = hashlib.pbkdf2_hmac(
        'sha256',  # The hash digest algorithm for HMAC
        password.encode('utf-8'),  # Convert the password to bytes
        salt,  # Provide the salt
        100000  # It is recommended to use at least 100,000 iterations of SHA-256
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
    new_hash = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt,
        100000
    )
    return new_hash == hashed_password


import hashlib # Import hashlib for password hashing

# Example Usage (Password Hashing)
if __name__ == '__main__':
    # Generate a session ID
    session_id = getSessionID()
    print(f"Generated Session ID: {session_id}")

    # Generate a secret key
    secret_key = generate_secret_key()
    print(f"Generated Secret Key: {secret_key}")

    # Example of password hashing and verification
    password = "my_secret_password"
    salt, hashed_password = hash_password(password)

    print(f"Salt: {salt.hex()}")  # Store the salt securely along with the hash
    print(f"Hashed Password: {hashed_password.hex()}")  # Store the hashed password securely

    # Verification
    correct = verify_password(password, salt, hashed_password)
    incorrect = verify_password("wrong_password", salt, hashed_password)

    print(f"Password verification (correct): {correct}")
    print(f"Password verification (incorrect): {incorrect}")

