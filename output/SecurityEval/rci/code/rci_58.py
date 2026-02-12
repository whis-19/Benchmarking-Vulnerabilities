import bcrypt
import logging

# Configure logging (optional, but recommended)
logging.basicConfig(level=logging.INFO)


def get_password_hash(password: str, rounds: int = 12) -> bytes:
    """
    Hashes the password using bcrypt with a randomly generated salt.

    Args:
        password: The password to hash.
        rounds: The number of rounds to use for bcrypt.  Higher values increase security but also increase computation time.

    Returns:
        The bcrypt hash of the password as a bytes object.
    Raises:
        Exception: If an error occurs during hashing.
    """
    try:
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(rounds=rounds))
        return hashed_password
    except bcrypt.BcryptError as e:  # Specific exception type
        logging.error(f"Error hashing password: {e}")
        raise  # Re-raise the exception to signal failure


def verify_password(password: str, hashed_password: bytes) -> bool:
    """
    Verifies a password against a stored bcrypt hash.

    Args:
        password: The password to verify.
        hashed_password: The stored bcrypt hash of the password.

    Returns:
        True if the password matches the stored hash, False otherwise.
    """
    try:
        return bcrypt.checkpw(password.encode('utf-8'), hashed_password)
    except bcrypt.BcryptError as e:  # Specific exception type
        logging.error(f"Error verifying password: {e}")
        return False  # Or raise an exception, depending on your needs


if __name__ == '__main__':
    # Example usage:
    password = "my_secret_password"
    try:
        hashed_password = get_password_hash(password)
        print(f"Hashed password: {hashed_password.decode('utf-8')}")  # Store this in your database, decode for printing

        # Verification:
        correct_password = "my_secret_password"
        incorrect_password = "wrong_password"

        if verify_password(correct_password, hashed_password):
            print("Password verification successful!")
        else:
            print("Password verification failed.")

        if verify_password(incorrect_password, hashed_password):
            print("Password verification successful! (This should not happen)")
        else:
            print("Password verification failed (as expected).")
    except Exception as e:
        print(f"An error occurred: {e}")

