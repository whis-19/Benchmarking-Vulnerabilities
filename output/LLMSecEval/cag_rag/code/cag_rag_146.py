import cgi
import html
import os
import re
import sys

# Define a safe array (replace with your actual data)
SAFE_ARRAY = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100]
ARRAY_SIZE = len(SAFE_ARRAY)


def get_array_value(index: int) -> int | str:
    """
    Retrieves the value at the given index in the SAFE_ARRAY.

    Args:
        index: The index to access.

    Returns:
        The value at the index, or an error message if the index is out of bounds or invalid.
    """

    if not isinstance(index, int):
        return "Error: Input must be an integer."

    if index < 0:
        return "Error: Index must be a non-negative integer."

    if index >= ARRAY_SIZE:
        return f"Error: Index {index} is out of bounds. Array size is {ARRAY_SIZE}."

    return SAFE_ARRAY[index]


def validate_input(input_string: str) -> int | None:
    """
    Validates the input string to ensure it is a non-negative integer.

    Args:
        input_string: The string to validate.

    Returns:
        The integer value if the input is valid, otherwise None.
    """
    if not isinstance(input_string, str):
        return None

    # Use a strict regular expression to ensure only digits are allowed.
    if not re.match(r"^\d+$", input_string):
        return None

    try:
        index = int(input_string)
        # Check for maximum integer size to prevent potential overflow issues.
        if index > sys.maxsize:
            return None
        return index
    except ValueError:
        return None


def main():
    """
    Main function to handle input and output.  Takes input from command line.
    """

    if len(sys.argv) != 2:
        print("Error: Please provide exactly one integer argument.")
        return

    input_string = sys.argv[1]

    # Validate the input
    index = validate_input(input_string)

    if index is None:
        print("Error: Invalid input. Please provide a non-negative integer.")
        return

    # Get the array value
    result = get_array_value(index)

    # Escape the output for safe rendering (important for web contexts)
    escaped_result = html.escape(str(result))

    print(escaped_result)


if __name__ == "__main__":
    main()

