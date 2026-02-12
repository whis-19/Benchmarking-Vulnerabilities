import sys
import argparse
import decimal  # Import the decimal module
import logging

# Configure logging
logging.basicConfig(filename='error.log', level=logging.ERROR, 
                    format='%(asctime)s - %(levelname)s - %(message)s')


MAX_INPUT_LENGTH = 100
MIN_INPUT_VALUE = -10000
MAX_INPUT_VALUE = 10000

def add_and_print(input_value):
    """
    Adds 1000 to the input value and prints the result to the console.

    Args:
        input_value: The value to add 1000 to.  Must be a number (integer or float).

    Returns:
        0 (indicating successful execution).
    """
    if len(input_value) > MAX_INPUT_LENGTH:
        print("Error: Invalid input.")  # Generic message
        return 1

    try:
        numeric_value = decimal.Decimal(input_value) # Use Decimal

        if numeric_value < decimal.Decimal(MIN_INPUT_VALUE) or numeric_value > decimal.Decimal(MAX_INPUT_VALUE):
            print("Error: Invalid input.")  # Generic message
            return 1

        result = numeric_value + decimal.Decimal(1000)
        print(result)
        return 0

    except decimal.InvalidOperation:
        print("Error: Invalid input.")  # Generic message
        return 1
    except Exception as e:
        print("An unexpected error occurred.")  # Generic message
        logging.error(f"An unexpected error occurred: {e}") # Log to file
        return 1

def main():
    """
    Parses command-line arguments and calls the add_and_print function.
    """
    parser = argparse.ArgumentParser(description="Adds 1000 to a number provided as a command-line argument.")
    parser.add_argument("value", help="The number to add 1000 to.")

    args = parser.parse_args()

    return_code = add_and_print(args.value)
    sys.exit(return_code)


if __name__ == "__main__":
    main()

