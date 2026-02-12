import secrets
import os
import logging
import sys

# Configure logging (important for security and debugging)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def secure_float_to_string(float_value, max_length=20):  # Added max_length
    """
    Converts a float to a string securely, limiting the string length.

    Args:
        float_value: The float to convert.
        max_length: The maximum length of the resulting string.

    Returns:
        A string representation of the float, or None if an error occurs.
    """
    try:
        # Input validation (check if it's actually a number)
        if not isinstance(float_value, (int, float)):
            logging.error("Invalid input: Not a number.")
            return None

        # Convert to string
        string_value = str(float_value)

        # Limit string length
        if len(string_value) > max_length:
            logging.warning(f"String length exceeds maximum allowed ({max_length}). Truncating.")
            string_value = string_value[:max_length]

        return string_value

    except Exception as e:
        logging.exception(f"An error occurred during float to string conversion: {e}")  # Log the full exception
        return None


def generate_secure_random_floats():
    """
    Generates three secure random floats and converts them to strings.
    """
    try:
        # Generate secure random floats using secrets.randbelow and scaling
        # secrets.randbelow(n) returns a random int in the range [0, n).
        # We scale this to get a float between 0 and 1 (approximately).
        random_float_a = secrets.randbelow(1000000) / 1000000.0
        random_float_b = secrets.randbelow(1000000) / 1000000.0
        random_float_c = secrets.randbelow(1000000) / 1000000.0

        # Convert to strings using the secure function
        str_a = secure_float_to_string(random_float_a)
        str_b = secure_float_to_string(random_float_b)
        str_c = secure_float_to_string(random_float_c)

        if str_a is None or str_b is None or str_c is None:
            logging.error("Failed to convert one or more floats to strings.")
            return None, None, None  # Or raise an exception

        # Output encoding (important!)  Let's assume UTF-8 for this example.
        # You might need to adjust this based on your application's needs.
        try:
            str_a_encoded = str_a.encode('utf-8', 'replace').decode('utf-8') # Handle encoding errors
            str_b_encoded = str_b.encode('utf-8', 'replace').decode('utf-8')
            str_c_encoded = str_c.encode('utf-8', 'replace').decode('utf-8')
        except UnicodeEncodeError as e:
            logging.error(f"Unicode encoding error: {e}")
            return None, None, None

        return str_a_encoded, str_b_encoded, str_c_encoded

    except Exception as e:
        logging.exception(f"An error occurred during random float generation and conversion: {e}")
        return None, None, None


if __name__ == "__main__":
    str_a, str_b, str_c = generate_secure_random_floats()

    if str_a and str_b and str_c:
        print(f"String a: {str_a}")
        print(f"String b: {str_b}")
        print(f"String c: {str_c}")
    else:
        print("Failed to generate secure random floats and convert them to strings.")

