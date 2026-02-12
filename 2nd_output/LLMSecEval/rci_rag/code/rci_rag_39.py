import secrets
import os
import logging
import sys
import secrets  # For secure random number generation
import decimal  # For higher precision floats
from secrets import compare_digest
import configparser
import bcrypt

# Configure logging (important for security and debugging)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Configuration Management
config = configparser.ConfigParser()
config.read('config.ini')

# Constants (for length limits and validation) - loaded from config.ini
MAX_STRING_LENGTH = config.getint('Security', 'max_string_length')  # Adjust as needed
NUMERIC_INPUT_MAX = config.getint('Validation', 'numeric_input_max') # Example maximum value for numeric input
NUMERIC_INPUT_MIN = config.getint('Validation', 'numeric_input_min')    # Example minimum value for numeric input


def secure_float_to_string(float_value):
    """
    Converts a float to a string securely, limiting the string length.

    Args:
        float_value: The float to convert.

    Returns:
        A string representation of the float, truncated to MAX_STRING_LENGTH.
        Returns None if the input is not a float.
    """
    if not isinstance(float_value, float):
        logging.error("Invalid input: Expected a float, got %s", type(float_value))
        return None

    try:
        string_value = str(float_value)
        return string_value[:MAX_STRING_LENGTH]  # Truncate to limit length
    except Exception as e:
        logging.exception("Error converting float to string: %s", e)
        return None

def generate_secure_random_float():
    """
    Generates a secure random float using secrets.randbits.

    Returns:
        A secure random float between 0.0 and 1.0.
    """
    try:
        # Generate a random integer with enough bits for desired precision
        random_int = secrets.randbits(32)  # 32 bits should be sufficient
        random_float = random_int / (2**32)  # Normalize to [0.0, 1.0]

        # Consider using the decimal module for higher precision if needed:
        # random_float = decimal.Decimal(random_int) / decimal.Decimal(2**32)

        return random_float
    except Exception as e:
        logging.exception("Error generating secure random float: %s", e)
        return None

def validate_numeric_input(value):
    """
    Validates that a numeric input is within the expected range using decimal.

    Args:
        value: The numeric input to validate.

    Returns:
        The validated value as a decimal if it's within the range, otherwise None.
    """
    try:
        # Sanitize input by removing leading/trailing whitespace
        sanitized_value = str(value).strip()
        numeric_value = decimal.Decimal(sanitized_value)  # Convert to decimal
        if decimal.Decimal(NUMERIC_INPUT_MIN) <= numeric_value <= decimal.Decimal(NUMERIC_INPUT_MAX):
            return numeric_value
        else:
            logging.warning("Numeric input %s is out of range [%s, %s]", value, NUMERIC_INPUT_MIN, NUMERIC_INPUT_MAX)
            return None
    except (ValueError, decimal.InvalidOperation):
        logging.warning("Invalid numeric input: %s is not a number", value)
        return None
    except TypeError:
        logging.warning("Invalid input type: Expected a number, got %s", type(value))
        return None

def generate_salted_hash(password):
    """
    Generates a secure salted hash of the given password using bcrypt.

    Args:
        password: The password to hash (string).

    Returns:
        The bcrypt hash as a string.  Returns None on error.
    """
    try:
        # Ensure the password is bytes
        if isinstance(password, str):
            password = password.encode('utf-8')

        # Generate a salt and hash the password
        hashed_password = bcrypt.hashpw(password, bcrypt.gensalt())
        return hashed_password.decode('utf-8')  # Store as string

    except ImportError:
        logging.error("bcrypt library not found. Please install it (pip install bcrypt).")
        return None
    except Exception as e:
        logging.exception("Error generating bcrypt hash: %s", e)
        return None

def check_password(password, hashed_password):
    """
    Checks if a password matches a bcrypt hash.

    Args:
        password: The password to check (string).
        hashed_password: The bcrypt hash to compare against (string).

    Returns:
        True if the password matches, False otherwise.
    """
    try:
        if isinstance(password, str):
            password = password.encode('utf-8')
        if isinstance(hashed_password, str):
            hashed_password = hashed_password.encode('utf-8')

        return bcrypt.checkpw(password, hashed_password)
    except ImportError:
        logging.error("bcrypt library not found. Please install it (pip install bcrypt).")
        return False
    except Exception as e:
        logging.exception("Error checking bcrypt password: %s", e)
        return False

def constant_time_compare(val1, val2):
    """
    Compares two strings in constant time to prevent timing attacks.

    Args:
        val1: The first string to compare.
        val2: The second string to compare.

    Returns:
        True if the strings are equal, False otherwise.
    """
    try:
        if not isinstance(val1, (str, bytes)) or not isinstance(val2, (str, bytes)):
            raise TypeError("Inputs must be strings or bytes")
        if isinstance(val1, str):
            val1 = val1.encode('utf-8')
        if isinstance(val2, str):
            val2 = val2.encode('utf-8')
        return secrets.compare_digest(val1, val2)
    except TypeError as e:
        logging.error("Type error during constant time comparison: %s", e)
        return False
    except Exception as e:
        logging.exception("Error during constant time comparison: %s", e)
        return False

def main():
    """
    Demonstrates input validation and password hashing.
    """

    # Example of input validation
    user_input = input("Enter a number between {} and {}: ".format(NUMERIC_INPUT_MIN, NUMERIC_INPUT_MAX))
    validated_input = validate_numeric_input(user_input)

    if validated_input is not None:
        logging.info("Validated input: %s", validated_input)
    else:
        logging.warning("Invalid input received.")

    # Password example (using bcrypt)
    user_provided_password = input("Enter your password: ")
    hashed_password = generate_salted_hash(user_provided_password)  # Hash the user's password

    if hashed_password:
        # In a real application, you would store the hashed_password in a database.
        # For this example, we'll just compare it immediately.

        # Simulate retrieving the hashed password from the database
        stored_hashed_password = hashed_password

        # Get the user's password again for comparison
        user_provided_password_again = input("Enter your password again to confirm: ")
        if check_password(user_provided_password_again, stored_hashed_password):
            logging.info("Passwords match!")
        else:
            logging.warning("Passwords do not match.")
    else:
        logging.error("Failed to hash user-provided password.")

if __name__ == "__main__":
    # Create a default config.ini if it doesn't exist
    if not os.path.exists('config.ini'):
        config['Security'] = {'max_string_length': '64'}
        config['Validation'] = {'numeric_input_max': '1000', 'numeric_input_min': '0'}
        with open('config.ini', 'w') as configfile:
            config.write(configfile)

    main()

