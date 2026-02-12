import os
import secrets
import hashlib
import base64
import logging
import binascii
from typing import Tuple
import re  # For password complexity

# Configure logging
logging.basicConfig(level=logging.INFO)

class PasswordVerificationError(Exception):
    pass

def generate_salt() -> bytes:
    """Generates a cryptographically secure random salt using a CSPRNG."""
    return secrets.token_bytes(16)  # 16 bytes = 128 bits

def is_password_complex(password: str) -> bool:
    """Checks if the password meets complexity requirements."""
    if len(password) < 8:
        return False
    if not re.search("[a-z]", password):
        return False
    if not re.search("[A-Z]", password):
        return False
    if not re.search("[0-9]", password):
        return False
    if not re.search("[!@#$%^&*()]", password):
        return False
    return True


def hash_password(password: str) -> Tuple[str, str, int]:
    """Hashes the password using PBKDF2-HMAC with a randomly generated salt.

    Args:
        password: The password to hash.

    Returns:
        A tuple containing the algorithm string, the combined hash string, and the key length.
    """

    if not is_password_complex(password):
        raise ValueError("Password does not meet complexity requirements.")

    algorithm = "pbkdf2_sha256"
    iterations_str = os.environ.get("PBKDF2_ITERATIONS")
    if iterations_str is None:
        iterations = 300000 # Secure default
        logging.warning("PBKDF2_ITERATIONS not set, using secure default of 300000")
    else:
        try:
            iterations = int(iterations_str)
            if iterations <= 100000:
                iterations = 300000
                logging.warning("PBKDF2_ITERATIONS is too low, using secure default of 300000")
        except ValueError:
            iterations = 300000
            logging.error("PBKDF2_ITERATIONS is not an integer, using secure default of 300000")

    key_length = 32      # Length of the derived key (hash) in bytes

    salt = generate_salt()  # Generate the salt here

    hashed_password = hashlib.pbkdf2_hmac(
        'sha256',  # Use SHA256 for the HMAC
        password.encode('utf-8'),  # Encode the password as bytes
        salt,
        iterations,
        dklen=key_length
    )

    # Base64 encode the salt and hashed password
    salt_b64 = base64.b64encode(salt).decode('utf-8')
    hashed_password_b64 = base64.b64encode(hashed_password).decode('utf-8')

    # Create the combined hash string
    combined_hash_string = f"{algorithm}={iterations}={key_length}={salt_b64}={hashed_password_b64}"

    return algorithm, combined_hash_string, key_length


def verify_password(password: str, combined_hash_string: str) -> bool:
    """Verifies a password against a stored combined hash string.

    Args:
        password: The password to verify.
        combined_hash_string: The stored combined hash string.

    Returns:
        True if the password matches the hash, False otherwise.
    """
    try:
        algorithm, iterations, key_length, salt_b64, hashed_password_b64 = combined_hash_string.split("=")
        iterations = int(iterations)
        key_length = int(key_length)
        salt = base64.b64decode(salt_b64)
        hashed_password = base64.b64decode(hashed_password_b64)

        # Re-hash the provided password with the stored salt
        new_hash = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt,
            iterations,
            dklen=key_length
        )

        # Compare the newly generated hash with the stored hash
        if secrets.compare_digest(new_hash, hashed_password):  # Use secrets.compare_digest for constant-time comparison
            # Algorithm Agility - Rehash with the current best algorithm if necessary
            current_best_algorithm = "pbkdf2_sha256"  # Replace with your current best algorithm
            if algorithm != current_best_algorithm:
                logging.info("Rehashing password with the current best algorithm.")
                new_algorithm, new_combined_hash_string, new_key_length = hash_password(password)
                # TODO: Update the user's password record in the database with new_combined_hash_string
                # (and potentially the algorithm and key_length if stored separately)
            return True
        else:
            return False


    except ValueError as e:
        logging.error(f"Invalid combined hash string format: {e}")
        raise PasswordVerificationError("Invalid hash string format") from e
    except TypeError as e:
        logging.error(f"Type error during password verification: {e}")
        raise PasswordVerificationError("Type error during verification") from e
    except binascii.Error as e:
        logging.error(f"Base64 decoding error: {e}")
        raise PasswordVerificationError("Base64 decoding error") from e
    except Exception as e:
        logging.exception(f"Unexpected error during password verification: {e}") # Log the full traceback
        raise PasswordVerificationError("Unexpected error during verification") from e


# Example Usage (for demonstration purposes only - adapt for your specific application)
if __name__ == '__main__':
    password = "my_secret_password"

    # Hashing the password
    algorithm, combined_hash_string, key_length = hash_password(password)

    print(f"Combined hash string: {combined_hash_string}")

    # Verification
    try:
        correct_password = verify_password(password, combined_hash_string)
        incorrect_password = verify_password("wrong_password", combined_hash_string)

        print(f"Correct password verification: {correct_password}")
        print(f"Incorrect password verification: {incorrect_password}")
    except PasswordVerificationError as e:
        print(f"Password verification failed: {e}")
    except ValueError as e:
        print(f"Password hashing failed: {e}")

