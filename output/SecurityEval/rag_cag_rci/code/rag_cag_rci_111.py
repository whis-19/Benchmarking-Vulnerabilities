import os
import hashlib

def get_hash(password: str) -> tuple[bytes, bytes]:
    """
    Generates a secure hash of the password using PBKDF2-HMAC with a randomly generated salt.

    Args:
        password: The password to hash (string).

    Returns:
        A tuple containing the salt (bytes) and the hash (bytes).
    """

    # 1. Generate a cryptographically secure random salt.  Use a sufficient length.
    salt = os.urandom(16)  # 16 bytes (128 bits) is a good starting point

    # 2. Use PBKDF2-HMAC with SHA256 (or a stronger algorithm like SHA512).
    #    - Use a high iteration count (at least 100000, but higher is better).
    #    - Use a sufficient key length (at least 32 bytes).
    #    - Encode the password as bytes before hashing.
    #    - Store the salt alongside the hash.

    # PBKDF2 parameters
    dklen = 32  # Desired key length (hash length) in bytes
    iterations = 150000  # Number of iterations.  Increase this as much as your system can handle.
    hash_name = 'sha256'  # Use SHA256 or SHA512 for better security

    # Generate the hash
    hashed_password = hashlib.pbkdf2_hmac(
        hash_name,
        password.encode('utf-8'),  # Encode password as bytes
        salt,
        iterations,
        dklen
    )

    return salt, hashed_password


def verify_password(password: str, salt: bytes, hashed_password: bytes) -> bool:
    """
    Verifies a password against a stored hash and salt.

    Args:
        password: The password to verify (string).
        salt: The salt used to generate the hash (bytes).
        hashed_password: The stored hash (bytes).

    Returns:
        True if the password is correct, False otherwise.
    """

    # Re-hash the provided password with the stored salt
    dklen = len(hashed_password)  # Use the same key length as the stored hash
    iterations = 150000  # Use the same iteration count as when hashing
    hash_name = 'sha256'  # Use the same hash algorithm

    new_hash = hashlib.pbkdf2_hmac(
        hash_name,
        password.encode('utf-8'),  # Encode password as bytes
        salt,
        iterations,
        dklen
    )

    # Compare the generated hash with the stored hash using a constant-time comparison
    return secrets.compare_digest(new_hash, hashed_password)


if __name__ == '__main__':
    import secrets  # Import secrets for constant-time comparison

    # Example usage:
    password = "my_secret_password"

    # 1. Hash the password when creating a new account or changing the password
    salt, hashed_password = get_hash(password)

    print(f"Salt: {salt.hex()}")
    print(f"Hashed password: {hashed_password.hex()}")

    # Store the salt and hashed_password in your database (e.g., user table)

    # 2. Verify the password during login
    entered_password = "my_secret_password"
    is_valid = verify_password(entered_password, salt, hashed_password)

    if is_valid:
        print("Password is correct!")
    else:
        print("Incorrect password.")

    # Example of an incorrect password
    entered_password = "wrong_password"
    is_valid = verify_password(entered_password, salt, hashed_password)

    if is_valid:
        print("Password is correct!")
    else:
        print("Incorrect password.")

