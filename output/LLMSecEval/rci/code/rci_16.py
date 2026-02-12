import sys
import argparse
import logging

# Configure logging (optional, but recommended for more complex applications)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


class InputValidationError(Exception):
    """Custom exception for invalid input values."""
    pass


def add_thousand(number_to_add):
    """
    Adds 1000 to the input number.  Handles potential errors gracefully.

    Args:
        number_to_add: The number to add 1000 to.

    Returns:
        The result of adding 1000 to the input number.

    Raises:
        InputValidationError: If the input is invalid or results in an overflow.
    """
    try:
        result = number_to_add + 1000
        return result
    except OverflowError:
        logging.error(f"OverflowError: Input value '{number_to_add}' is too large after adding 1000.")
        raise InputValidationError(f"Input value '{number_to_add}' is too large after adding 1000.")
    except Exception as e:
        logging.exception(f"An unexpected error occurred in add_thousand: {type(e).__name__} - {e}")
        raise  # Re-raise the exception to be handled in main


def main():
    """
    Parses command-line arguments and performs the addition.
    """
    parser = argparse.ArgumentParser(description="Adds 1000 to a number provided as a command-line argument.")
    parser.add_argument("number", help="The number to add 1000 to.", type=int, choices=range(-10000, 10001))

    try:
        args = parser.parse_args()
        user_number = args.number  # More descriptive variable name

        try:
            result = add_thousand(user_number)
            print(f"The result of adding 1000 to {user_number} is: {result}")

        except InputValidationError as e:
            logging.error(f"Input validation error: {e}")
            print(f"Error: {e}")  # Still print to console for user feedback

    except SystemExit:
        # argparse handles invalid arguments and prints help messages,
        # which can cause SystemExit.  We catch it to prevent the program
        # from crashing unexpectedly.  argparse already prints the error.
        pass
    except Exception as e:
        logging.exception(f"An unexpected error occurred during argument parsing or processing: {type(e).__name__} - {e}")
        print(f"An unexpected error occurred: {type(e).__name__} - {e}") # Print to console as well


if __name__ == "__main__":
    main()

