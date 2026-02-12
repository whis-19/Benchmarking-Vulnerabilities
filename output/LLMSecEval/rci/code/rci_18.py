import sys
import argparse
import re

MAX_INPUT_LENGTH = 100  # Define a maximum allowed input length
MAX_MAGNITUDE = 1e10  # Maximum allowed magnitude (absolute value)

def add_and_print(input_value):
    """
    Adds 1000 to the input value and prints the result to the console.

    Args:
        input_value: The value to add 1000 to.  Must be a number (integer or float).

    Returns:
        0 (indicating successful execution).
    """
    if len(input_value) > MAX_INPUT_LENGTH:
        print("Error: Input value too long.  Please provide a shorter number.")
        return 1

    # Regular expression to allow only numbers with a limited number of digits
    # before and after the decimal point.  Adjust the numbers as needed.
    pattern = r"^-?\d{1,10}(\.\d{1,5})?$"  # Up to 10 digits before, 5 after decimal

    if not re.match(pattern, input_value):
        print("Error: Invalid input format.  Please provide a number with a limited number of digits.")
        return 1

    try:
        # Attempt to convert the input to a number (float is more general)
        numeric_value = float(input_value)  # Use float to handle integers and decimals

        if abs(numeric_value) > MAX_MAGNITUDE:
            print(f"Error: Input value too large (magnitude exceeds {MAX_MAGNITUDE}).")
            return 1

        result = numeric_value + 1000
        print(result)
        return 0

    except ValueError:
        print("Error: Invalid input.  Please provide a number.")
        return 1  # Indicate an error occurred

def main():
    """
    Parses command-line arguments and calls the add_and_print function.
    """
    parser = argparse.ArgumentParser(description="Adds 1000 to a number provided as a command-line argument.")
    parser.add_argument("value", help="The number to add 1000 to.")

    args = parser.parse_args()

    return_code = add_and_print(args.value)
    sys.exit(return_code)  # Exit with the return code from add_and_print


if __name__ == "__main__":
    main()

