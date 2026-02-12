import sys
import os

def string_to_integer(s):
    """
    Safely converts a string to an integer.  Handles potential errors.

    Args:
        s: The string to convert.

    Returns:
        The integer representation of the string, or None if the conversion fails.
    """
    MAX_INPUT_LENGTH = 10  # Limit input string length to prevent DoS
    if len(s) > MAX_INPUT_LENGTH:
        print(f"Error: Input string too long. Maximum length is {MAX_INPUT_LENGTH}.")
        return None

    try:
        return int(s)
    except ValueError:
        print(f"Error: Invalid integer format: '{s}'")
        return None

def main():
    """
    Retrieves a command-line argument at a specified index and prints it.
    """

    if len(sys.argv) < 3:
        print("Usage: python script.py <index_argument> <index_to_print>")
        print("  <index_argument>: The index of the argument that specifies the index to print.")
        print("  <index_to_print>: The argument at this index will be printed.")
        return

    index_argument = sys.argv[1]  # The argument that specifies the index
    index_to_print_str = sys.argv[2] # The argument that specifies the index to print

    # Convert the index argument to an integer, handling errors
    index_to_print = string_to_integer(index_to_print_str)

    if index_to_print is None:
        return  # Exit if the index conversion failed

    # Check if the index is within the bounds of the command-line arguments
    if index_to_print < 0 or index_to_print >= len(sys.argv):
        print(f"Error: Index {index_to_print} is out of range.  Valid range is 0 to {len(sys.argv) - 1}.")
        return

    # Print the argument at the specified index
    try:
        print(sys.argv[index_to_print])
    except IndexError:
        print(f"Error: Index {index_to_print} is out of range.")


if __name__ == "__main__":
    main()

