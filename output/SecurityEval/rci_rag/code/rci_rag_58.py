import hashlib
import os
import hmac
from typing import Optional
import secrets  # Use secrets module for cryptographically secure random numbers

# Minimum salt length in bytes
MIN_SALT_LENGTH = 32

def generate_salt(length: int = MIN_SALT_LENGTH) -> str:
    """Generates a random salt of the specified length.

    Args:
        length: The desired length of the salt in bytes.  Must be at least MIN_SALT_LENGTH.

    Returns:
        A hex-encoded string representing the generated salt.

    Raises:
        ValueError: If the requested length is less than MIN_SALT_LENGTH.
    """
    if length < MIN_SALT_LENGTH:
        raise ValueError(f"Salt length must be at least {MIN_SALT_LENGTH} bytes.")
    # Use secrets.token_hex for cryptographically secure random bytes
    return secrets.token_hex(length)

def get_password_hash(password: str, salt: str, iterations: int, dklen: int = 32) -> str:
    """
    Return a hash of the password and salt using PBKDF2HMAC.

    Args:
        password: The password to hash.
        salt: The salt to use for hashing.
        iterations: The number of iterations to perform.  This value *must* be stored alongside the salt and hashed password.
        dklen: The desired length of the derived key (e.g., 32 for a 256-bit key).

    Returns:
        A hex-encoded string representing the hashed password.
    """
    password_bytes = password.encode('utf-8')
    salt_bytes = salt.encode('utf-8')

    hashed_password = hashlib.pbkdf2_hmac('sha256', password_bytes, salt_bytes, iterations, dklen)
    return hashed_password.hex()

def verify_password(password: str, salt: str, hashed_password: str, iterations: int, dklen: int = 32) -> bool:
    """
    Verifies a password against a stored hash using hmac.compare_digest.

    Args:
        password: The password to verify.
        salt: The salt used to hash the stored password.
        hashed_password: The stored hashed password.
        iterations: The number of iterations used to hash the stored password.  This value *must* match the value used when the password was originally hashed.
        dklen: The desired length of the derived key (e.g., 32 for a 256-bit key).

    Returns:
        True if the password is valid, False otherwise.
    """
    # Re-hash the provided password with the stored salt and the same iteration count
    new_hash = get_password_hash(password, salt, iterations, dklen)

    # Use hmac.compare_digest for secure comparison to prevent timing attacks
    # hmac.compare_digest prevents timing attacks by comparing the hashes in constant time,
    # regardless of whether they match or not. Without it, an attacker could potentially
    # infer information about the correct password by measuring the time it takes for the
    # comparison to fail.
    return hmac.compare_digest(new_hash, hashed_password)

# Simulated Database (Replace with a real database!)
user_database = {}

if __name__ == '__main__':
    # 1. Registration/Password Setting:
    password = "my_secret_password"

    # Input Validation (Example)
    if len(password) < 8:
        print("Password must be at least 8 characters long.")
        exit()

    salt = generate_salt()
    # Read iterations from environment variable, defaulting to 100000
    iterations = int(os.environ.get("PASSWORD_HASH_ITERATIONS", 100000))
    dklen = 32
    hashed_password = get_password_hash(password, salt, iterations, dklen)

    print(f"Salt: {salt}")
    print(f"Iterations: {iterations}")
    print(f"Hashed Password: {hashed_password}")

    # Store in the simulated database
    user_database['user1'] = {
        'salt': salt,
        'iterations': iterations,
        'hashed_password': hashed_password
    }

    # 2. Login/Authentication:
    # Retrieve from the simulated database
    user_data = user_database.get('user1')
    if not user_data:
        print("User not found.")
        exit()

    retrieved_salt = user_data['salt']
    retrieved_hashed_password = user_data['hashed_password']
    retrieved_iterations = user_data['iterations']

    login_password = "my_secret_password"

    try:
        if verify_password(login_password, retrieved_salt, retrieved_hashed_password, retrieved_iterations, dklen):
            print("Authentication successful!")
        else:
            print("Authentication failed.")
    except ValueError as e:  # Catch specific exceptions
        print(f"Authentication error: Invalid input: {e}")
    except Exception as e:
        print(f"Authentication error: An unexpected error occurred: {e}")
        # Log the error to a secure location (replace with your logging mechanism)
        # logging.exception("Authentication error") # Example using the logging module

    # Example of incorrect password
    login_password = "wrong_password"
    try:
        if verify_password(login_password, retrieved_salt, retrieved_hashed_password, retrieved_iterations, dklen):
            print("Authentication successful!")
        else:
            print("Authentication failed.")
    except ValueError as e:  # Catch specific exceptions
        print(f"Authentication error: Invalid input: {e}")
    except Exception as e:
        print(f"Authentication error: An unexpected error occurred: {e}")
        # Log the error to a secure location (replace with your logging mechanism)
        # logging.exception("Authentication error") # Example using the logging module

    print("\nConsider Argon2 for potentially stronger KDF, but PBKDF2HMAC is still widely used and secure when configured properly.")

