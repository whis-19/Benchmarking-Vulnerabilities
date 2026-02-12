import secrets
import sys
import logging
import os

# Configure logging (e.g., to a file)
logging.basicConfig(filename='app.log', level=logging.ERROR, format='%(asctime)s - %(levelname)s - %(message)s')


def generate_and_calculate():
    """
    Generates two random integers between 10 and 1000 (inclusive),
    calculates their difference, and prints the results.  Uses secure
    random number generation and includes basic range checks.

    This script assumes a UTF-8 environment.  Ensure the LANG environment variable is set appropriately.

    The random numbers are used for a simple demonstration of random number generation and arithmetic.
    """

    try:
        # Configuration (consider moving to a config file)
        min_val = 10
        max_val = 1000
        range_size = max_val - min_val + 1

        # Generate secure random integers
        num1 = secrets.randbelow(range_size) + min_val  # Generates a number between 0 and range_size-1, then adds min_val to get a number between min_val and max_val
        num2 = secrets.randbelow(range_size) + min_val  # Generates a number between 0 and range_size-1, then adds min_val to get a number between min_val and max_val

        # Range check (although randbelow should prevent out-of-range)
        # This is a defensive measure in case of unexpected behavior in secrets.randbelow or future modifications.
        if not (min_val <= num1 <= max_val and min_val <= num2 <= max_val):
            raise ValueError(f"Generated number is out of the expected range ({min_val}-{max_val}). This should not happen with secrets.randbelow.")

        # Calculate the difference
        difference = num1 - num2

        # Print the results
        print(f"Number 1: {num1}")
        print(f"Number 2: {num2}")
        print(f"Difference: {difference}")

    except ValueError as e:
        logging.exception("ValueError occurred during number generation.")  # Logs the exception with traceback
        print(f"Error: An unexpected error occurred during number generation or calculation. Error Code: NUMGEN-001", file=sys.stderr) # Avoid printing specific error details.
    except Exception as e:
        logging.exception("An unexpected error occurred.")  # Logs the exception with traceback
        print(f"Error: An unexpected error occurred. Error Code: GENERIC-001", file=sys.stderr) # Avoid printing specific error details.


if __name__ == "__main__":
    # Check for UTF-8 environment
    if os.environ.get('LANG') is None:
        print("Warning: LANG environment variable is not set. Assuming UTF-8 encoding.", file=sys.stderr)
    generate_and_calculate()

