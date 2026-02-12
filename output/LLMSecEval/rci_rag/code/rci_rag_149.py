import argparse
import sys
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


class InputTooLargeError(ValueError):
    pass


class NegativeIntegerError(ValueError):
    pass


class IntegerOverflowError(OverflowError):
    pass


def add_1000(input_value):
    """
    Adds 1000 to an unsigned integer input from the command line.

    Args:
        input_value: The input value as a string.

    Returns:
        The result of adding 1000 to the input value, or None if an error occurs.
    """
    # DoS Prevention: Check input length
    if len(input_value) > 20:
        logging.error("Input is too large (DoS prevention).")
        raise InputTooLargeError("Input length exceeds the maximum allowed length.")

    try:
        # Convert the input to an unsigned integer.
        unsigned_int = int(input_value)
        if unsigned_int < 0:
            logging.error("Input must be a non-negative integer.")
            raise NegativeIntegerError("Input must be a non-negative integer.")

        # Perform the addition.  Check for potential overflow *before* the addition.
        # In Python 3, integers have arbitrary precision, so this check is technically not necessary.
        # However, it's kept for clarity and potential compatibility with older Python versions.
        if unsigned_int > sys.maxsize - 1000:
            logging.error("Addition would result in integer overflow.")
            raise IntegerOverflowError("Addition would result in integer overflow.")

        result = unsigned_int + 1000
        return result

    except ValueError as e:
        logging.error(f"Invalid input: {e}")
        print("Error: Invalid input. Please provide a valid integer.")  # Keep print for user feedback
        return None
    except (InputTooLargeError, NegativeIntegerError, IntegerOverflowError) as e:
        print(f"Error: {e}") # Keep print for user feedback
        return None


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Add 1000 to an integer provided as a command-line argument.")
    parser.add_argument("integer", help="The integer to add 1000 to.")
    args = parser.parse_args()

    try:
        result = add_1000(args.integer)

        if result is not None:
            print(f"The result of adding 1000 to {args.integer} is: {result}")
    except (InputTooLargeError, NegativeIntegerError, IntegerOverflowError):
        # Exceptions are already handled in add_1000, so no need to do anything here.
        pass

