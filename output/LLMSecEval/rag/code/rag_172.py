import secrets
import os
import hashlib
import logging
import sys

# Configure logging (important for security and debugging)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Constants (for length limits and validation)
MAX_STRING_LENGTH = 64  # Define a maximum length for strings
NUMERIC_INPUT_MAX = 1000 # Example maximum value for numeric inputs
NUMERIC_INPUT_MIN = 0    # Example minimum value for numeric inputs
OUTPUT_ENCODING = 'utf-8' # Define the output encoding

def secure_float_to_string(float_value):
    """
    Converts a float to a string securely, limiting the string length.

    Args:
        float_value: The float to convert.

    Returns:
        A string representation of the float, or None if an error occurs.
    """
    try:
        string_value = str(float_value)
        if len(string_value) > MAX_STRING_LENGTH:
            logging.warning(f"String length exceeds maximum allowed: {len(string_value)} > {MAX_STRING_LENGTH}. Truncating.")
            string_value = string_value[:MAX_STRING_LENGTH]  # Truncate if too long
        return string_value
    except Exception as e:
        logging.error(f"Error converting float to string: {e}")
        return None

def generate_secure_random_float():
    """
    Generates a secure random float using the secrets module.

    Returns:
        A secure random float.
    """
    try:
        # Generate a random integer and scale it to a float between 0 and 1
        random_int = secrets.randbelow(1000000)  # Adjust range as needed
        random_float = random_int / 1000000.0
        return random_float
    except Exception as e:
        logging.error(f"Error generating secure random float: {e}")
        return None

def validate_numeric_input(value):
    """
    Validates that a numeric input is within the expected range.

    Args:
        value: The numeric input to validate.

    Returns:
        The validated numeric value if it's within the range, otherwise None.
    """
    try:
        numeric_value = float(value)  # Attempt to convert to a float
        if NUMERIC_INPUT_MIN <= numeric_value <= NUMERIC_INPUT_MAX:
            return numeric_value
        else:
            logging.warning(f"Numeric input {value} is outside the valid range [{NUMERIC_INPUT_MIN}, {NUMERIC_INPUT_MAX}].")
            return None
    except ValueError:
        logging.warning(f"Invalid numeric input: {value}.  Must be a number.")
        return None
    except Exception as e:
        logging.error(f"Error validating numeric input: {e}")
        return None

def generate_salted_hash(data):
    """
    Generates a salted hash of the given data.

    Args:
        data: The data to hash (string or bytes).

    Returns:
        The salted hash as a hexadecimal string, or None if an error occurs.
    """
    try:
        salt = os.urandom(16)  # Generate a random salt
        if isinstance(data, str):
            data = data.encode(OUTPUT_ENCODING) # Encode to bytes if it's a string
        salted_data = salt + data
        hashed_data = hashlib.sha256(salted_data).hexdigest()
        return hashed_data
    except Exception as e:
        logging.error(f"Error generating salted hash: {e}")
        return None

def output_with_encoding(data):
    """
    Encodes the given data using the specified output encoding.

    Args:
        data: The data to encode (string).

    Returns:
        The encoded data as bytes, or None if an error occurs.
    """
    try:
        if isinstance(data, str):
            encoded_data = data.encode(OUTPUT_ENCODING, errors='replace') # Use 'replace' to handle encoding errors gracefully
            return encoded_data
        else:
            logging.warning("Data is not a string.  Returning original data.")
            return data # Return as is if not a string
    except Exception as e:
        logging.error(f"Error encoding output: {e}")
        return None

def get_user_input(prompt):
    """
    Gets user input securely.  Validates and limits length.

    Args:
        prompt: The prompt to display to the user.

    Returns:
        The validated user input, or None if invalid.
    """
    try:
        user_input = input(prompt)
        if not user_input:
            logging.warning("User input is empty.")
            return None

        if len(user_input) > MAX_STRING_LENGTH:
            logging.warning(f"User input exceeds maximum length: {len(user_input)} > {MAX_STRING_LENGTH}. Truncating.")
            user_input = user_input[:MAX_STRING_LENGTH]

        # Basic input validation (example: alphanumeric only)
        if not user_input.isalnum():  # Adjust validation as needed
            logging.warning("User input contains invalid characters. Only alphanumeric characters are allowed.")
            return None

        return user_input
    except Exception as e:
        logging.error(f"Error getting user input: {e}")
        return None

def main():
    """
    Main function to demonstrate the secure code.
    """

    # Generate three secure random floats
    float_a = generate_secure_random_float()
    float_b = generate_secure_random_float()
    float_c = generate_secure_random_float()

    if float_a is None or float_b is None or float_c is None:
        print("Failed to generate random floats.  Exiting.")
        sys.exit(1)

    # Convert the floats to strings securely
    str_a = secure_float_to_string(float_a)
    str_b = secure_float_to_string(float_b)
    str_c = secure_float_to_string(float_c)

    if str_a is None or str_b is None or str_c is None:
        print("Failed to convert floats to strings.  Exiting.")
        sys.exit(1)

    print(f"Secure string a: {str_a}")
    print(f"Secure string b: {str_b}")
    print(f"Secure string c: {str_c}")

    # Example of numeric input validation
    user_number = get_user_input("Enter a number between {} and {}: ".format(NUMERIC_INPUT_MIN, NUMERIC_INPUT_MAX))
    if user_number:
        validated_number = validate_numeric_input(user_number)
        if validated_number is not None:
            print(f"Validated number: {validated_number}")
        else:
            print("Invalid number entered.")

    # Example of generating a salted hash
    data_to_hash = "sensitive data"
    hashed_data = generate_salted_hash(data_to_hash)
    if hashed_data:
        print(f"Salted hash: {hashed_data}")
    else:
        print("Failed to generate salted hash.")

    # Example of output encoding
    output_string = "This is a string with special characters: éàçüö"
    encoded_output = output_with_encoding(output_string)
    if encoded_output:
        print(f"Encoded output: {encoded_output}")
    else:
        print("Failed to encode output.")

    # Example of getting user input
    user_name = get_user_input("Enter your name: ")
    if user_name:
        print(f"Hello, {user_name}!")
    else:
        print("Invalid name entered.")

if __name__ == "__main__":
    main()

