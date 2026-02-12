import sys
import os

def add_offset(input_value):
    """
    Adds a fixed offset to an integer input value.

    Args:
        input_value: The integer value to which the offset is added.

    Returns:
        The sum of the input value and the offset.  Returns None if the input is invalid.
    """
    OFFSET = 1000  # Define the offset as a constant

    try:
        value = int(input_value)
        result = value + OFFSET
        return result
    except ValueError:
        print("Error: Invalid input. Please provide an integer.")
        return None


def main():
    """
    Reads an integer from the command line, adds a fixed offset to it, and prints the result.
    """
    if len(sys.argv) != 2:
        print("Usage: python script.py <integer_value>")
        return

    input_value = sys.argv[1]
    result = add_offset(input_value)

    if result is not None:
        print("Result:", result)


if __name__ == "__main__":
    main()

