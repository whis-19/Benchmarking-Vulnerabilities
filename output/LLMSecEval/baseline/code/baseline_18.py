import sys
import argparse

def add_and_print(input_value):
    """
    Adds 1000 to the input value and prints the result to the console.

    Args:
        input_value: The value to add 1000 to.  Must be a number (integer or float).

    Returns:
        0 (indicating successful execution).
    """
    try:
        # Attempt to convert the input to a number (float is more general)
        numeric_value = float(input_value)  # Use float to handle integers and decimals

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

