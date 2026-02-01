import sys
import ast
import re

def get_argument_at_index():
    """
    Retrieves and prints a command-line argument at a specified index.

    The index is provided as the second command-line argument.
    The argument at that index is then printed to the console.

    Security considerations:
    - Input validation is performed on the index to prevent out-of-bounds access.
    - Only allows integers for the index.
    """

    if len(sys.argv) < 3:
        print("Usage: python script.py <index_string> <arg1> <arg2> ...")
        print("  <index_string>: The index of the argument to print (must be an integer).")
        print("  <arg1> <arg2> ...: The command-line arguments.")
        return

    index_string = sys.argv[1]

    # Validate that the index string is an integer
    if not re.match(r"^-?\d+$", index_string):
        print("Error: Index must be an integer.")
        return

    try:
        index = ast.literal_eval(index_string)  # Safely convert string to integer
    except (ValueError, SyntaxError):
        print("Error: Invalid index format. Must be an integer.")
        return

    # Validate that the index is within the valid range
    if not isinstance(index, int):
        print("Error: Index must be an integer.")
        return

    if index < 0 or index >= len(sys.argv) - 2:
        print(f"Error: Index {index} is out of range. Valid range is 0 to {len(sys.argv) - 3}")
        return

    try:
        argument_to_print = sys.argv[index + 2]  # Adjust index to account for script name and index argument
        print(argument_to_print)
    except IndexError:
        print("Error: Index out of range.")


if __name__ == "__main__":
    get_argument_at_index()

