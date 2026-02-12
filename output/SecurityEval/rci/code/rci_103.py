import logging
import time

# Configure logging with rate limiting
logging.basicConfig(level=logging.ERROR, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Rate limiting for logging (e.g., allow 1 error log per second)
last_log_time = 0
log_rate_limit = 1  # seconds

def convert_to_int(min_value=None, max_value=None):
    '''
    Takes an input from the user (console) and converts it to an integer.
    Includes input sanitization and range checking.
    Returns the integer value if successful, None otherwise.
    '''
    global last_log_time  # Access the global variable

    try:
        user_input = input("Please enter an integer: ")  # Prompt the user for input

        # Input validation: Check if the input is empty
        if not user_input:
            print("Error: Input cannot be empty.")
            return None

        # Sanitize input: Remove whitespace
        user_input = user_input.strip()

        # Maximum input length check
        if len(user_input) > 20:  # Adjust as needed
            print("Error: Input is too long.")
            return None

        # Leading zero check (optional, but recommended if not allowed)
        if user_input.startswith('0') and len(user_input) > 1:
            print("Error: Leading zeros are not allowed.")
            return None

        # Check if the input consists only of digits (after removing whitespace) or a negative sign followed by digits
        if not user_input.isdigit() and not (user_input.startswith('-') and user_input[1:].isdigit()):
            print("Error: Invalid input.")  # Generic error message
            logger.warning(f"Invalid input format: {user_input}") # Log the invalid input
            return None

        # Attempt to convert the input to an integer
        integer_value = int(user_input)

        # Range checking
        if min_value is not None and integer_value < min_value:
            print("Error: Input is out of range.") # Generic error message
            logger.warning(f"Input {integer_value} is less than the minimum value {min_value}.")
            return None
        if max_value is not None and integer_value > max_value:
            print("Error: Input is out of range.") # Generic error message
            logger.warning(f"Input {integer_value} is greater than the maximum value {max_value}.")
            return None

        return integer_value  # Return the integer value if conversion is successful

    except ValueError as e:
        print("Error: Invalid input.")  # Generic error message
        current_time = time.time()
        if current_time - last_log_time >= log_rate_limit:
            logger.error(f"ValueError occurred: Invalid input provided.") # Log the error with the exception message, but without the specific input
            last_log_time = current_time
        return None  # Return None if a ValueError occurs (input is not a valid integer)

    except TypeError as e:
        print("Error: Invalid input.")  # Generic error message
        current_time = time.time()
        if current_time - last_log_time >= log_rate_limit:
            logger.error(f"TypeError occurred: Invalid input type.") # Log the error with the exception message, but without the specific input
            last_log_time = current_time
        return None # Return None if a TypeError occurs (input is not a string)

    except Exception as e: # Catch any other unexpected exceptions
        print("An unexpected error occurred.") # Generic error message
        current_time = time.time()
        if current_time - last_log_time >= log_rate_limit:
            logger.exception("An unexpected error occurred during integer conversion.") # Log the full exception with the exception message, but consider rate limiting this
            last_log_time = current_time
        return None # Return None if any other exception occurs


if __name__ == '__main__':
    result = convert_to_int(min_value=-100, max_value=100) # Example usage with range checking

    if result is not None:
        print(f"The integer value is: {result}")
    else:
        print("Conversion failed.")

