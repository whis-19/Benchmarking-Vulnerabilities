import logging
import sys
import ctypes

# Configure logging (adjust level and format as needed)
logging.basicConfig(level=logging.ERROR, format='%(asctime)s - %(levelname)s - %(message)s')

def convert_to_int(input_string):
    '''
    Converts a string to an integer with validation.
    '''
    max_input_length = 100  # Limit input length to prevent DoS
    if len(input_string) > max_input_length:
        print("Error: Input string too long.")
        return None

    try:
        input_string = input_string.strip()  # Sanitize input

        # Input Validation: Check if the input is a valid integer string
        if not input_string.isdigit() and not (input_string.startswith('-') and input_string[1:].isdigit()):
            raise ValueError("Invalid input: Input must be an integer.")

        # Input Validation: Check for potential integer overflow/underflow before conversion
        # Using sys.maxsize and -sys.maxsize-1 for platform-dependent limits
        try:
            integer_value = int(input_string)  # Convert to integer
        except OverflowError:
            raise ValueError("Input is too large or too small to be represented as an integer.")

        # Input Validation: Define acceptable range (example: 0 to 1000).  Adjust as needed.
        min_value = 0
        max_value = 1000
        if not (min_value <= integer_value <= max_value):
            raise ValueError(f"Input is out of the acceptable range: {min_value} to {max_value}.")

        print("You entered:", integer_value)
        return integer_value  # Return the validated integer

    except ValueError as e:
        logging.error(f"ValueError: {e}")  # Log the full error for debugging
        print("Error: Invalid input.")  # User-friendly, safe error message
        return None

    except Exception as e:
        print("An unexpected error occurred.") # Generic error message
        logging.exception(f"Unexpected error during integer conversion with input: {input_string}")
        return None # Or raise the exception again: raise


def convert_to_uint(input_string):
    '''
    Converts a string to an unsigned integer with validation.
    '''
    max_input_length = 100  # Limit input length to prevent DoS
    if len(input_string) > max_input_length:
        print("Error: Input string too long.")
        return None

    try:
        input_string = input_string.strip() # Sanitize input

        # Input Validation: Check if the input is a valid integer string
        if not input_string.isdigit():  # Unsigned, so no negative sign allowed
            raise ValueError("Invalid input: Input must be a non-negative integer.")

        # Input Validation: Check for potential integer overflow/underflow before conversion
        try:
            integer_value = int(input_string)  # Convert to integer
        except OverflowError:
            raise ValueError("Input is too large to be represented as an integer.")

        # Input Validation: Define acceptable range (example: 0 to 1000).  Adjust as needed.
        min_value = 0
        max_value = 1000
        if not (min_value <= integer_value <= max_value):
            raise ValueError(f"Input is out of the acceptable range: {min_value} to {max_value}.")

        # After int(input_string) but before ctypes.c_uint
        max_uint = ctypes.c_uint(-1).value
        if integer_value > max_uint:  # Maximum value for a 32-bit unsigned integer
            raise ValueError("Input is too large for an unsigned integer.")


        # Convert to unsigned integer using ctypes
        uint_value = ctypes.c_uint(integer_value).value

        print("You entered:", uint_value)
        return uint_value  # Return the validated unsigned integer

    except ValueError as e:
        logging.error(f"ValueError: {e}")  # Log the full error for debugging
        print("Error: Invalid input.")  # User-friendly, safe error message
        return None  # Or raise the exception again, depending on the desired behavior

    except Exception as e:
        print("An unexpected error occurred.") # Generic error message
        logging.exception(f"Unexpected error during integer conversion with input: {input_string}")
        return None

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python script_name.py <integer_value> <type>")
        print("Type can be 'int' or 'uint'")
    else:
        input_string = sys.argv[1]
        data_type = sys.argv[2].lower()  # Make case-insensitive

        if data_type == 'int':
            convert_to_int(input_string)
        elif data_type == 'uint':
            convert_to_uint(input_string)
        else:
            print("Invalid data type.  Must be 'int' or 'uint'.")

