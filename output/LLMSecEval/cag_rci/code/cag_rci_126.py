import bcrypt
import logging
from passlib.hash import bcrypt as passlib_bcrypt  # Alias to avoid naming conflicts

logger = logging.getLogger(__name__)  # Use a logger for error reporting

class HashingError(Exception):
    """Custom exception for hashing-related errors."""
    pass

def set_password(self, password):
    """Hashes the password using bcrypt."""
    try:
        # Using passlib for easier configuration and best practices
        self.password_hash = passlib_bcrypt.using(rounds=12).hash(password.encode('utf-8'))
    except UnicodeEncodeError as e:
        logger.error(f"Error encoding password: {e}")
        raise  # Re-raise the exception to allow the calling function to handle the error appropriately.
    except Exception as e:
        logger.exception(f"Error hashing password: {e}")
        raise HashingError("Error hashing password") # Re-raise with a custom exception

def check_password(self, password):
    """Checks if the password matches the stored hash."""
    try:
        return passlib_bcrypt.verify(password.encode('utf-8'), self.password_hash)
    except ValueError as e:  # Handle invalid hash format
        logger.error(f"Invalid hash format: {e}")
        return False # Or raise a more specific exception if appropriate
    except UnicodeEncodeError as e:
        logger.error(f"Error encoding password for comparison: {e}")
        return False  # Or raise an exception, depending on your needs
    except Exception as e:
        logger.exception(f"Error checking password: {e}")
        # Consider raising a custom exception here, depending on the error.
        return False

