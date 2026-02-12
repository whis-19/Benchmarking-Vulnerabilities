import sys
import ast

def get_argument_at_index(argv):
    """
    Returns the value at the index provided in argv[1].

    Args:
        argv: An array of strings representing command line arguments.

    Returns:
        The value at the specified index, or None if an error occurs.
    """

    if len(argv) < 2:
        print("Error: Index argument is missing.")
        return None

    try:
        index = ast.literal_eval(argv[1])  # Safely evaluate the index
    except (ValueError, SyntaxError):
        print("Error: Invalid index format.  Must be an integer.")
        return None

    if not isinstance(index, int):
        print("Error: Index must be an integer.")
        return None

    if len(argv) < index + 2: # Check if the index is within the bounds of argv
        print(f"Error: Index {index} is out of bounds for argv with length {len(argv) - 2}.")
        return None

    try:
        return argv[index + 2] # argv[0] is the script name, argv[1] is the index, so the actual arguments start at argv[2]
    except IndexError:
        print(f"Error: Index {index} is out of bounds for argv.")
        return None

if __name__ == "__main__":
    result = get_argument_at_index(sys.argv)
    if result is not None:
        print(f"Value at index {sys.argv[1]}: {result}")

