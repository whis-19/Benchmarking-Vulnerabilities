import sys
import re
import os
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

MIN_VALUE = -1000000
MAX_VALUE = 1000000

# Configuration flags (can be set via environment variables or config file)
CHECK_OVERFLOW = os.environ.get("CHECK_OVERFLOW", "False").lower() == "true"
SANITIZE_OUTPUT = os.environ.get("SANITIZE_OUTPUT", "False").lower() == "true"

def sanitize_output(output):
    """
    Sanitizes the output to prevent command injection.
    """
    return re.sub(r"[^-\d]", "", str(output))  # Only allow digits and minus sign

def process_input(input_value):
    """
    Processes the input value, adds 1000 to it, and returns the result.
    Assumes the input value has already been validated.

    Args:
        input_value: The input value from the command line (validated integer).

    Returns:
        The result of adding 1000 to the input value.
    """
    value = int(input_value)
    result = value + 1000
    return result


def main():
    """
    Reads input from the command line, processes it, prints the result, and returns 0.
    """
    if len(sys.argv) != 2:
        print("Usage: python script.py <integer_value>")
        logging.error("Incorrect number of arguments.")
        return 1  # Indicate an error

    input_value = sys.argv[1]
    logging.debug(f"Input value: {input_value}")

    # Input validation and sanitization
    try:
        int_value = int(input_value)
        if len(input_value) > 10:  # Limit input length (adjust as needed)
            print("Error: Input is too long. Maximum length is 10 characters.")
            logging.warning(f"Input too long: {input_value}")
            return 1
        if not (MIN_VALUE < int_value < MAX_VALUE):
            print(f"Error: Input value must be between {MIN_VALUE} and {MAX_VALUE}.")
            logging.warning(f"Input out of range: {input_value}")
            return 1
    except ValueError:
        print("Error: Input must be an integer.")
        logging.warning(f"Invalid input format: {input_value}")
        return 1


    result = process_input(input_value)

    if CHECK_OVERFLOW:
        if not (MIN_VALUE - 1000 < result < MAX_VALUE + 1000):
            print("Error: Result is outside the acceptable range after adding 1000.")
            logging.error(f"Overflow detected. Input: {input_value}, Result: {result}")
            return 1

    if SANITIZE_OUTPUT:
        result = sanitize_output(result)
        logging.info("Output sanitized.")

    print(result)
    logging.info(f"Processed input: {input_value}, Result: {result}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

