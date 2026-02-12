import hashlib
import secrets
import logging
import os  # Import os for environment variables

# Configure logging (replace with your preferred logging setup)
logging.basicConfig(level=logging.INFO)

class InvalidStoredValue(Exception):
    """Custom exception raised when the stored password hash is malformed."""
    pass

def getHash(password):
    '''
    Create a hash of the password with a salt using PBKDF2-HMAC-SHA256.

    Args:
        password (str): The password to hash.

    Returns:
        str: A string containing the iterations, salt, and the hash, separated by a colon.
             Format: "iterations:salt:hash"
    '''

    # Generate a random salt.  Using secrets.token_bytes is preferred for security.
    salt = secrets.token_bytes(16)  # 16 bytes = 128 bits

    # Derive the key using PBKDF2-HMAC-SHA256.
    # - password.encode('utf-8'):  Encode the password to bytes.  Crucial for consistent hashing.
    # - salt: The salt.
    # - iterations:  Number of iterations.  Higher is better, but slower.  100000 is a good starting point.  Adjust based on performance.
    # - dklen:  Desired key length (hash length).  32 bytes (256 bits) is a common choice for SHA256.
    iterations = int(os.environ.get("PBKDF2_ITERATIONS", 100000))  # Get iterations from environment variable

    # Validate iteration count
    if not 10000 <= iterations <= 1000000:
        logging.warning(f"Iteration count {iterations} is outside the recommended range (10000-1000000). Using default 100000.")
        iterations = 100000

    dklen = 32
    hashed_password = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, iterations, dklen)

    # Encode the salt and hash to hexadecimal strings for storage.
    salt_hex = salt.hex()
    hashed_password_hex = hashed_password.hex()

    # Return the iterations, salt, and hash, separated by a colon.  This format makes it easy to split later.
    return f"{iterations}:{salt_hex}:{hashed_password_hex}"


def verifyPassword(password, stored_value):
    '''
    Verifies a password against a stored hash (iterations:salt:hash).

    Args:
        password (str): The password to verify.
        stored_value (str): The stored iterations, salt, and hash (iterations:salt:hash).

    Returns:
        bool: True if the password matches the stored hash, False otherwise.

    Raises:
        InvalidStoredValue: If the stored value is malformed.
    '''

    try:
        iterations, salt_hex, hashed_password_hex = stored_value.split(":")
        iterations = int(iterations)
        salt = bytes.fromhex(salt_hex)
        stored_hash = bytes.fromhex(hashed_password_hex)

        # Validate salt length
        if len(salt) != 16:
            logging.error(f"Invalid salt length: {len(salt)}. Expected 16, got {len(salt)}.")
            raise InvalidStoredValue("Invalid salt length")


    except ValueError as e:
        logging.error(f"Malformed stored value: {stored_value}. Error: {e}")
        raise InvalidStoredValue("Invalid stored value format") from e # Preserve original exception

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
    try:
        is_valid = verifyPassword("some_password", "invalid_format")
        print(f"Password is valid (invalid format): {is_valid}")
    except InvalidStoredValue as e:
        print(f"Error verifying password (invalid format): {e}")

    # Example of setting the iteration count via environment variable
    os.environ["PBKDF2_ITERATIONS"] = "200000"
    hashed_value_high_iter = getHash(password)
    print(f"Hashed password with higher iterations: {hashed_value_high_iter}")

    os.environ["PBKDF2_ITERATIONS"] = "5000" # Test invalid iteration count
    hashed_value_invalid_iter = getHash(password)
    print(f"Hashed password with invalid iterations: {hashed_value_invalid_iter}")

