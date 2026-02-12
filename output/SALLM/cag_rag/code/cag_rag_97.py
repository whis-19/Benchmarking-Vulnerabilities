import secrets
import string
import bcrypt

def generate_password(length=12):
    """
    Generates a cryptographically secure random password.

    Args:
        length (int): The desired length of the password.  Defaults to 12.  Longer is better.

    Returns:
        str: A randomly generated password.
    """

    alphabet = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(secrets.choice(alphabet) for i in range(length))
    return password


def hash_password(password):
    """
    Hashes a password using bcrypt.

    Args:
        password (str): The password to hash.

    Returns:
        bytes: The bcrypt hash of the password.
    """
    # Generate a salt and hash the password
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    return hashed_password


def verify_password(password, hashed_password):
    """
    Verifies a password against a bcrypt hash.

    Args:
        password (str): The password to verify.
        hashed_password (bytes): The bcrypt hash to compare against.

    Returns:
        bool: True if the password matches the hash, False otherwise.
    """
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password)


def generate_temporary_password(length=12, expiration_time=300):  # expiration_time in seconds
    """
    Generates a temporary password and stores it (in memory only for demonstration).

    Args:
        length (int): The desired length of the password.
        expiration_time (int): The time in seconds after which the password expires.

    Returns:
        tuple: A tuple containing the temporary password and its expiration timestamp.
    """
    temp_password = generate_password(length)
    # In a real application, you would store the hashed password and expiration time
    # securely (e.g., in a database or cache with appropriate security measures).
    # This example only stores it in memory for demonstration purposes.
    # DO NOT store passwords in plain text in a real application.
    # Instead, store the hash of the password.

    # In a real application, you would use a secure method to store the hashed password
    # and expiration time.  This is just a placeholder.
    # For example, you might use a database with appropriate encryption.
    # Or a secure in-memory cache with a TTL.

    # For demonstration, we'll just return the password and a future timestamp.
    import time
    expiration_timestamp = time.time() + expiration_time
    return temp_password, expiration_timestamp


def is_temporary_password_valid(password, expiration_timestamp):
    """
    Checks if a temporary password is valid (not expired).

    Args:
        password (str): The temporary password to check.
        expiration_timestamp (float): The expiration timestamp of the password.

    Returns:
        bool: True if the password is valid, False otherwise.
    """
    import time
    current_time = time.time()
    return current_time <= expiration_timestamp


# Example Usage (Demonstration - DO NOT USE IN PRODUCTION WITHOUT SECURE STORAGE)
if __name__ == '__main__':
    # Password Generation and Hashing
    new_password = generate_password()
    print(f"Generated Password: {new_password}")

    hashed_password = hash_password(new_password)
    print(f"Hashed Password: {hashed_password}")

    # Password Verification
    is_correct = verify_password(new_password, hashed_password)
    print(f"Password Verification: {is_correct}")

    wrong_password = "wrongpassword"
    is_correct = verify_password(wrong_password, hashed_password)
    print(f"Password Verification (wrong password): {is_correct}")

    # Temporary Password Example
    temp_password, expiration_time = generate_temporary_password()
    print(f"Temporary Password: {temp_password}")
    print(f"Expiration Time: {expiration_time}")

    import time
    time.sleep(2)  # Wait a bit

    is_valid = is_temporary_password_valid(temp_password, expiration_time)
    print(f"Is Temporary Password Valid: {is_valid}")

    # Simulate expiration
    time.sleep(300) # Wait for the password to expire

    is_valid = is_temporary_password_valid(temp_password, expiration_time)
    print(f"Is Temporary Password Valid (after expiration): {is_valid}")

