import time
import secrets
import os
import string  # Import string module for password generation
import uuid
import bcrypt
import logging

# Initialize logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


def currentTime():
    '''
    Print the current processor time in seconds.
    '''
    print(f"Current processor time: {time.process_time()} seconds")


def generate_secure_password(length=16):
    """
    Generates a cryptographically secure random password of the specified length.

    Args:
        length: The desired length of the password (default: 16).  Must be a positive integer.

    Returns:
        A string containing the generated password.

    Raises:
        ValueError: If length is not a positive integer.
    """
    if not isinstance(length, int) or length <= 0:
        raise ValueError("Length must be a positive integer.")

    alphabet = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(alphabet) for i in range(length))


def generate_secure_token(length=32):
    """
    Generates a cryptographically secure random token of the specified length.

    Args:
        length: The desired length of the token (default: 32). Must be a positive integer.

    Returns:
        A string containing the generated token (hexadecimal representation).

    Raises:
        ValueError: If length is not a positive integer.
    """
    if not isinstance(length, int) or length <= 0:
        raise ValueError("Length must be a positive integer.")
    return secrets.token_hex(length // 2)  # token_hex takes number of bytes


def generate_random_number_in_range(lower_bound, upper_bound):
    """
    Generates a cryptographically secure random integer within a specified range.

    Args:
        lower_bound: The lower bound of the range (inclusive).
        upper_bound: The upper bound of the range (inclusive).

    Returns:
        A random integer within the specified range.

    Raises:
        ValueError: If lower_bound is not less than upper_bound.
    """
    if lower_bound >= upper_bound:
        raise ValueError("Lower bound must be less than upper bound.")

    range_size = upper_bound - lower_bound + 1
    random_number = secrets.randbelow(range_size)
    return lower_bound + random_number


def securely_hash_password(password, salt=None, rounds=12):
    """
    Securely hashes a password using bcrypt.  If no salt is provided, a new one is generated.

    Args:
        password: The password to hash (string).
        salt: Optional salt to use for hashing (bytes).  If None, a new salt is generated.
        rounds: The number of rounds to use for bcrypt.  Higher values are more secure but slower.

    Returns:
        A tuple containing the salt (bytes) and the hashed password (bytes).
    """

    if salt is None:
        salt = bcrypt.gensalt(rounds=rounds)

    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    return salt, hashed_password


def verify_password(password, salt, hashed_password):
    """
    Verifies a password against a stored hash using bcrypt.

    Args:
        password: The password to verify (string).
        salt: The salt used to hash the password (bytes).
        hashed_password: The stored hashed password (bytes).

    Returns:
        True if the password matches the hash, False otherwise.
    """

    try:
        return bcrypt.checkpw(password.encode('utf-8'), hashed_password)
    except ValueError:
        # Handle cases where the hash is invalid (e.g., different hashing algorithm)
        return False


def securely_compare_strings(string1, string2):
    """
    Securely compares two strings to prevent timing attacks.

    Args:
        string1: The first string to compare.
        string2: The second string to compare.

    Returns:
        True if the strings are equal, False otherwise.
    """
    return secrets.compare_digest(string1, string2)


def generate_uuid_secure():
    """
    Generates a cryptographically secure UUID (Universally Unique Identifier).

    Returns:
        A string containing the generated UUID.
    """
    return str(uuid.uuid4())


def securely_delete_file(filepath, passes=3):
    """
    Securely deletes a file by overwriting it multiple times with random data
    before unlinking.

    Args:
        filepath: The path to the file to delete.
        passes: The number of overwrite passes (default: 3).
    """
    try:
        file_size = os.path.getsize(filepath)
        with open(filepath, "wb") as f:
            for _ in range(passes):
                f.write(os.urandom(file_size))  # Overwrite with random data
        os.remove(filepath)  # Unlink the file
        # Attempt to remove the directory if it's empty
        try:
            os.rmdir(os.path.dirname(filepath))
        except OSError:
            # Directory not empty or other error, ignore
            pass

    except FileNotFoundError:
        logger.warning(f"File not found: {filepath}")
    except (OSError, IOError) as e:
        logger.error(f"Error securely deleting file: {e}", exc_info=True)
    except Exception as e:
        logger.exception(f"Unexpected error during secure deletion: {e}") # Log the full exception


if __name__ == '__main__':
    currentTime()

    # Example usage of secure password generation
    try:
        password = generate_secure_password()
        print(f"Generated secure password: {password}")
        password = generate_secure_password(20)
        print(f"Generated secure password of length 20: {password}")
        # password = generate_secure_password(-1) # This will raise a ValueError
    except ValueError as e:
        print(f"Error generating password: {e}")

    # Example usage of secure token generation
    try:
        token = generate_secure_token()
        print(f"Generated secure token: {token}")
        token = generate_secure_token(64)
        print(f"Generated secure token of length 64: {token}")
        # token = generate_secure_token(-1) # This will raise a ValueError
    except ValueError as e:
        print(f"Error generating token: {e}")

    # Example usage of secure random number generation
    try:
        random_number = generate_random_number_in_range(1, 100)
        print(f"Generated secure random number between 1 and 100: {random_number}")
        # random_number = generate_random_number_in_range(100, 1) # This will raise a ValueError
    except ValueError as e:
        print(f"Error generating random number: {e}")

    # Example usage of secure password hashing
    password_to_hash = "my_secret_password"
    salt, hashed_password = securely_hash_password(password_to_hash)
    print(f"Salt: {salt}")
    print(f"Hashed password: {hashed_password}")

    # Example usage of password verification
    is_valid = verify_password(password_to_hash, salt, hashed_password)
    print(f"Password verification: {is_valid}")

    # Example usage of secure string comparison
    string1 = "hello"
    string2 = "hello"
    string3 = "world"
    print(f"Securely comparing '{string1}' and '{string2}': {securely_compare_strings(string1, string2)}")
    print(f"Securely comparing '{string1}' and '{string3}': {securely_compare_strings(string1, string3)}")

    # Example usage of UUID generation
    uuid_str = generate_uuid_secure()
    print(f"Generated UUID: {uuid_str}")

    # Example usage of secure file deletion (create a dummy file first)
    dummy_file = "dummy.txt"
    try:
        with open(dummy_file, "w") as f:
            f.write("This is some sensitive data.")
        securely_delete_file(dummy_file)
        print(f"Securely deleted file: {dummy_file}")
    except Exception as e:
        print(f"Error during file creation or deletion: {e}")

