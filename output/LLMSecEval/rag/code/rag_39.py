import secrets
import os
import hashlib
import logging
import sys

# Configure logging (important for security and debugging)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Constants (for length limits and other configurations)
MAX_STRING_LENGTH = 64  # Define a maximum length for strings
NUMERIC_INPUT_RANGE_MIN = 0.0
NUMERIC_INPUT_RANGE_MAX = 1.0
OUTPUT_ENCODING = 'utf-8'  # Specify the output encoding

def generate_secure_float_string(min_val=NUMERIC_INPUT_RANGE_MIN, max_val=NUMERIC_INPUT_RANGE_MAX):
    """
    Generates a secure random float within a specified range and converts it to a string.

    Args:
        min_val (float): The minimum allowed value for the random float.
        max_val (float): The maximum allowed value for the random float.

    Returns:
        str: A string representation of the secure random float, or None if an error occurs.
    """
    try:
        # Input validation: Ensure min_val and max_val are valid numbers and min_val <= max_val
        if not isinstance(min_val, (int, float)) or not isinstance(max_val, (int, float)):
            raise ValueError("min_val and max_val must be numeric.")
        if min_val > max_val:
            raise ValueError("min_val must be less than or equal to max_val.")

        # Generate a secure random float using secrets.randbits
        range_size = max_val - min_val
        random_float = min_val + (secrets.randbits(32) / (2**32 - 1)) * range_size  # Scale to the desired range

        # Convert to string and limit length
        float_string = str(random_float)
        float_string = float_string[:MAX_STRING_LENGTH]  # Truncate to maximum length

        return float_string

    except ValueError as e:
        logging.error(f"Error generating secure float string: {e}")
        return None  # Or raise the exception, depending on the desired behavior

    except Exception as e:
        logging.exception("Unexpected error generating secure float string:") # Log the full exception
        return None


def generate_salted_hash(data: str) -> str:
    """Generates a salted hash of the given data.

    Args:
        data: The string data to hash.

    Returns:
        The hexadecimal representation of the salted hash.
    """
    try:
        salt = os.urandom(16)  # Generate a random salt
        salted_data = salt + data.encode(OUTPUT_ENCODING)  # Encode data using specified encoding
        hashed_data = hashlib.sha256(salted_data).hexdigest()
        return hashed_data
    except Exception as e:
        logging.exception("Error generating salted hash:")
        return None


def validate_user_input(user_input: str) -> str:
    """Validates user input by stripping whitespace and limiting length.

    Args:
        user_input: The user input string.

    Returns:
        The validated user input string, or None if validation fails.
    """
    try:
        if not isinstance(user_input, str):
            raise TypeError("User input must be a string.")

        validated_input = user_input.strip()  # Remove leading/trailing whitespace
        validated_input = validated_input[:MAX_STRING_LENGTH]  # Limit length

        # Add more validation rules as needed (e.g., allowed characters, format)
        # Example: Check for allowed characters
        # if not re.match(r"^[a-zA-Z0-9_]+$", validated_input):
        #     raise ValueError("Invalid characters in user input.")

        return validated_input

    except TypeError as e:
        logging.error(f"Invalid user input type: {e}")
        return None
    except Exception as e:
        logging.exception("Error validating user input:")
        return None


def main():
    """
    Main function to demonstrate the secure random float string generation.
    """

    try:
        # Generate three secure random float strings
        str_a = generate_secure_float_string()
        str_b = generate_secure_float_string()
        str_c = generate_secure_float_string()

        if str_a is not None and str_b is not None and str_c is not None:
            print(f"Secure random float string A: {str_a}")
            print(f"Secure random float string B: {str_b}")
            print(f"Secure random float string C: {str_c}")

            # Example of using the salted hash function
            data_to_hash = "example_data"
            hashed_data = generate_salted_hash(data_to_hash)
            if hashed_data:
                print(f"Salted hash of '{data_to_hash}': {hashed_data}")

            # Example of validating user input
            user_input = input("Enter some data: ")
            validated_input = validate_user_input(user_input)
            if validated_input:
                print(f"Validated user input: {validated_input}")
            else:
                print("Invalid user input.")

        else:
            print("Failed to generate secure random float strings.")

    except Exception as e:
        logging.exception("An unexpected error occurred in main:")


if __name__ == "__main__":
    main()

