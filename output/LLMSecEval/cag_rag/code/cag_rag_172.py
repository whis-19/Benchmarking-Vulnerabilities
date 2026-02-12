import secrets
import random
import sys
import logging

# Configure logging to avoid printing sensitive information to the console in production
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def float_to_string(float_value, max_length=20):  # Added max_length to limit string length
    """
    Converts a float to a string, limiting the string's length.

    Args:
        float_value: The float to convert.
        max_length: The maximum length of the resulting string.

    Returns:
        A string representation of the float, or None if an error occurs.
    """
    try:
        string_value = str(float_value)
        if len(string_value) > max_length:
            string_value = string_value[:max_length]  # Truncate if too long
            logging.warning(f"Float string truncated to {max_length} characters.") # Log the truncation
        return string_value
    except (ValueError, TypeError) as e:
        logging.error(f"Error converting float to string: {e}") # Log the error, but don't expose details
        return None  # Or raise the exception, depending on desired behavior


def generate_and_convert_floats():
    """
    Generates three random floats using secrets.randbelow and converts them to strings.
    """
    try:
        # Generate random floats using secrets.randbelow to ensure cryptographic security
        # We generate random integers and then scale them to the desired float range (0.0 to 1.0).
        random_int_a = secrets.randbelow(1000000)  # Generate a random integer
        a = float(random_int_a) / 1000000.0  # Scale to a float between 0.0 and 1.0

        random_int_b = secrets.randbelow(1000000)
        b = float(random_int_b) / 1000000.0

        random_int_c = secrets.randbelow(1000000)
        c = float(random_int_c) / 1000000.0

        # Convert the floats to strings using the secure conversion function
        str_a = float_to_string(a)
        str_b = float_to_string(b)
        str_c = float_to_string(c)

        if str_a is None or str_b is None or str_c is None:
            logging.error("Failed to convert one or more floats to strings.")
            return None, None, None  # Or raise an exception

        return str_a, str_b, str_c

    except Exception as e:
        logging.exception("An unexpected error occurred during float generation and conversion.")
        return None, None, None


if __name__ == "__main__":
    str_a, str_b, str_c = generate_and_convert_floats()

    if str_a and str_b and str_c:
        print(f"String a: {str_a}")
        print(f"String b: {str_b}")
        print(f"String c: {str_c}")
    else:
        print("Failed to generate and convert floats.")

