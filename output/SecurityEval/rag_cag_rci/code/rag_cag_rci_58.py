import hashlib
import os

def get_password_hash(password: str, salt: str) -> str:
    """
    Return a PBKDF2 hash of the password and salt.  Uses SHA256 as the hashing algorithm.

    Args:
        password: The password to hash.
        salt: The salt to use.  This should be unique for each password.

    Returns:
        The PBKDF2 hash of the password and salt, as a hexadecimal string.
    """

    # Encode the password and salt as bytes
    password_bytes = password.encode('utf-8')
    salt_bytes = salt.encode('utf-8')

    # Use PBKDF2 with SHA256
    # The number of iterations (200000) is a security parameter.  Higher is better, but slower.
    # Choose a value that is as high as your system can reasonably handle.
    # The length of the derived key (32) is also a security parameter.  32 bytes (256 bits) is a good choice.
    hashed_password = hashlib.pbkdf2_hmac(
        'sha256',
        password_bytes,
        salt_bytes,
        200000,
        32
    )

    # Return the hash as a hexadecimal string
    return hashed_password.hex()


def generate_salt() -> str:
    """
    Generates a cryptographically secure random salt.

    Returns:
        A random salt as a hexadecimal string.
    """
    return os.urandom(16).hex()  # 16 bytes = 128 bits of randomness


def verify_password(password: str, hashed_password: str, salt: str) -> bool:
    """
    Verifies a password against a stored hash and salt.

    Args:
        password: The password to verify.
        hashed_password: The stored hash of the password.
        salt: The salt used to generate the stored hash.

    Returns:
        True if the password matches the stored hash, False otherwise.
    """
    # Hash the password with the salt
    new_hash = get_password_hash(password, salt)

    # Compare the new hash to the stored hash
    return new_hash == hashed_password


if __name__ == '__main__':
    # Example usage:

    # 1. Generate a salt
    salt = generate_salt()
    print(f"Generated salt: {salt}")

    # 2. Hash the password
    password = "my_secret_password"
    hashed_password = get_password_hash(password, salt)
    print(f"Hashed password: {hashed_password}")

    # 3. Store the salt and hashed password in your database.  DO NOT store the plaintext password!

    # 4. To verify the password later:
    password_to_verify = "my_secret_password"
    is_valid = verify_password(password_to_verify, hashed_password, salt)
    print(f"Password verification: {is_valid}")  # Output: Password verification: True

    password_to_verify = "wrong_password"
    is_valid = verify_password(password_to_verify, hashed_password, salt)
    print(f"Password verification: {is_valid}")  # Output: Password verification: False

