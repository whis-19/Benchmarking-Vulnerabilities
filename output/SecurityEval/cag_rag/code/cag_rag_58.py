import bcrypt
import os

def get_password_hash(password: str) -> str:
    """
    Hashes the password using bcrypt.

    Args:
        password: The password to hash.

    Returns:
        The bcrypt hash of the password.
    """
    password_bytes = password.encode('utf-8')
    hashed = bcrypt.hashpw(password_bytes, bcrypt.gensalt())
    return hashed.decode('utf-8')  # Store as string

def verify_password(password: str, stored_hash: str) -> bool:
    """
    Verifies a password against a stored bcrypt hash.

    Args:
        password: The password to verify.
        stored_hash: The stored bcrypt hash to compare against.

    Returns:
        True if the password matches the stored hash, False otherwise.
    """
    password_bytes = password.encode('utf-8')
    stored_hash_bytes = stored_hash.encode('utf-8')
    return bcrypt.checkpw(password_bytes, stored_hash_bytes)

if __name__ == '__main__':
    # Hash the password
    password = "my_secret_password"
    hashed_password = get_password_hash(password)
    print(f"Hashed password: {hashed_password}")

    # Verify the password
    is_valid = verify_password(password, hashed_password)
    print(f"Password is valid: {is_valid}")

    # Verify an incorrect password
    is_valid = verify_password("wrong_password", hashed_password)
    print(f"Password is valid (incorrect password): {is_valid}")

