import secrets
import os
import hashlib
import logging
import sys
import decimal

# Configure logging (important for security and debugging)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Constants (for length limits and validation)
MAX_STRING_LENGTH = 64  # Adjust as needed
NUMERIC_INPUT_MAX = 1000 # Example maximum value for numeric input
NUMERIC_INPUT_MIN = 0    # Example minimum value for numeric input

def secure_float_to_string(float_value):
    """
    Converts a float to a string securely, limiting the string length.

    Args:
        float_value: The float to convert.

    Returns:
        A string representation of the float, truncated to MAX_STRING_LENGTH.
        Returns None if the input is not a float, NaN, or Infinity.
        Raises ValueError if the string representation exceeds MAX_STRING_LENGTH.
    """
    if not isinstance(float_value, float):
        logging.error("Invalid input: Expected a float, got %s", type(float_value))
        return None

    if float_value != float_value:  # Check for NaN
        logging.error("Invalid input: Float is NaN")
        return None

    if float_value == float('inf') or float_value == float('-inf'): # Check for Infinity
        logging.error("Invalid input: Float is Infinity")
        return None

    try:
        string_value = str(float_value)
        if len(string_value) > MAX_STRING_LENGTH:
            logging.warning("Float string representation exceeds MAX_STRING_LENGTH. Raising ValueError.")
            raise ValueError("Float string representation exceeds maximum length.")
        return string_value
    except ValueError as e:
        logging.error("Error converting float to string: %s", e)
        return None
    except Exception as e:
        logging.exception("Error converting float to string: %s", e)
        return None

def generate_secure_random_float():
    """
    Generates a secure random float using secrets.randbits.

    Returns:
        A secure random float between 0.0 and 1.0.
        The precision of this float is limited by the number of bits used to generate the random integer (32 bits in this case).
        If higher precision is required, more bits should be used.
        Intended use case: Generating a random number for non-cryptographic purposes, such as simulations or games.
        For security-sensitive applications, consider using secrets.randbits with a larger number of bits or random.SystemRandom().
    """
    try:
        # Generate a random integer with enough bits for desired precision
        random_int = secrets.randbits(32)  # 32 bits should be sufficient
        random_float = random_int / float(2**32)  # Normalize to [0.0, 1.0] - clearer intent
        return random_float
    except Exception as e:
        logging.exception("Error generating secure random float: %s", e)
        return None

def validate_numeric_input(value):
    """
    Validates that a numeric input is within the expected range.

    Args:
        value: The numeric input to validate.

    Returns:
        The validated value as a decimal if it's within the range, otherwise None.
        Note: This function does not explicitly address timing attacks.
        If the validated input were to be displayed on a web page without proper sanitization, it could be vulnerable to XSS attacks.
        If the validated input is used in a database query, it's vulnerable to SQL injection if not properly parameterized.
        If the validated input is used in a system command, it's vulnerable to command injection.
    """
    try:
        numeric_value = decimal.Decimal(value)  # Attempt to convert to a Decimal
        if NUMERIC_INPUT_MIN <= numeric_value <= NUMERIC_INPUT_MAX:
            return numeric_value
        else:
            logging.warning("Numeric input %s is out of range [%s, %s]", value, NUMERIC_INPUT_MIN, NUMERIC_INPUT_MAX)
            return None
    except decimal.InvalidOperation:
        logging.warning("Invalid numeric input: %s is not a number", value)
        return None
    except TypeError:
        logging.warning("Invalid input type: Expected a number, got %s", type(value))
        return None

def generate_salted_hash(data):
    """
    Generates a salted hash of the given data.

    Args:
        data: The data to hash (string or bytes).

    Returns:
        A tuple containing the hexadecimal representation of the salt and the salted hash.
        IMPORTANT: The salt MUST be stored alongside the hash for verification.
        For password storage, consider using bcrypt or Argon2 instead of SHA256.
    """
    try:
        salt = secrets.token_bytes(16)  # Generate a random salt using secrets
        if isinstance(data, str):
            data = data.encode('utf-8')  # Encode to bytes if it's a string
        salted_data = salt + data
        hashed_data = hashlib.sha256(salted_data).hexdigest()
        return salt.hex(), hashed_data  # Return both salt and hash
    except Exception as e:
        logging.exception("Error generating salted hash: %s", e)
        return None, None

def main():
    """
    Generates three random floats, converts them to strings, and demonstrates input validation and hashing.
    """

    # Generate random floats
    a = generate_secure_random_float()
    b = generate_secure_random_float()
    c = generate_secure_random_float()

    if a is None or b is None or c is None:
        logging.error("Failed to generate random floats. Exiting.")
        sys.exit(1)

    # Convert floats to strings securely
    str_a = secure_float_to_string(a)
    str_b = secure_float_to_string(b)
    str_c = secure_float_to_string(c)

    if str_a is None or str_b is None or str_c is None:
        logging.error("Failed to convert floats to strings. Exiting.")
        sys.exit(1)

    logging.info("Generated strings: str_a=%s, str_b=%s, str_c=%s", str_a, str_b, str_c)

    # Example of input validation
    user_input = input("Enter a number between {} and {}: ".format(NUMERIC_INPUT_MIN, NUMERIC_INPUT_MAX))
    # WARNING: The input() function is inherently dangerous.  It allows arbitrary code execution if the user enters a malicious string (in Python 2.x; in Python 3.x it's safer, but still prone to unexpected input).  Never use input() in production code without careful validation.
    validated_input = validate_numeric_input(user_input)

    if validated_input is not None:
        logging.info("Validated input: %s", validated_input)
    else:
        logging.warning("Invalid input received.")

    # Example of generating a salted hash
    data_to_hash = "This is some sensitive data."
    salt, hashed_data = generate_salted_hash(data_to_hash)

    if hashed_data:
        logging.info("Salted hash: %s", hashed_data)
        logging.info("Salt: %s", salt)
    else:
        logging.error("Failed to generate salted hash.")

if __name__ == "__main__":
    main()

