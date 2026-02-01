import sys
import re
import ast

def get_argument_at_index(arguments):
    """
    Retrieves and prints the command line argument at a specified index.

    Args:
        arguments: A list of command line arguments.

    Returns:
        None. Prints the argument at the specified index to the console.
        Prints an error message if the index is invalid or out of range.
    """

    if len(arguments) < 2:
        print("Error: Please provide an index as the second argument.")
        return

    index_str = arguments[1]

    # Validate that the index is a non-negative integer.  Use a strict regex.
    if not re.match(r"^\d+$", index_str):
        print("Error: The index must be a non-negative integer.")
        return

    try:
        index = int(index_str)
    except ValueError:
        print("Error: Invalid index format.")
        return

    if index < 0:
        print("Error: Index must be non-negative.")
        return

    if index >= len(arguments):
        print(f"Error: Index {index} is out of range.  The number of arguments is {len(arguments)}.")
        return

    print(arguments[index])


if __name__ == "__main__":
    get_argument_at_index(sys.argv)

