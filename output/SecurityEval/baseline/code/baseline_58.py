import hashlib
import secrets

def get_password_hash(password: str, salt: str) -> str:
    """
    Return a SHA-256 hash of the password and salt.

    Args:
        password: The password to hash.
        salt: The salt to use.

    Returns:
        The SHA-256 hash of the password and salt as a hexadecimal string.
    """
    password_bytes = password.encode('utf-8')
    salt_bytes = salt.encode('utf-8')
    combined = salt_bytes + password_bytes
    hashed_password = hashlib.sha256(combined).hexdigest()
    return hashed_password


def generate_salt() -> str:
    """
    Generates a cryptographically secure random salt.

    Returns:
        A random salt as a hexadecimal string.
    """
    return secrets.token_hex(16)  # 16 bytes = 128 bits


def verify_password(password: str, hashed_password: str, salt: str) -> bool:
    """
    Verifies a password against a stored hash and salt.

    Args:
        password: The password to verify.
        hashed_password: The stored hash.
        salt: The salt used to generate the hash.

    Returns:
        True if the password matches the hash, False otherwise.
    """
    return get_password_hash(password, salt) == hashed_password


if __name__ == '__main__':
    # Example usage:
    password = "my_secret_password"
    salt = generate_salt()
    hashed_password = get_password_hash(password, salt)

    print(f"Salt: {salt}")
    print(f"Hashed password: {hashed_password}")

    # Verification:
    correct_password = verify_password(password, hashed_password, salt)
    incorrect_password = verify_password("wrong_password", hashed_password, salt)

    print(f"Password verification (correct): {correct_password}")
    print(f"Password verification (incorrect): {incorrect_password}")

