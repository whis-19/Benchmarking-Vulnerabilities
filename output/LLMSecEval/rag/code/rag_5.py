import sys
import os

def get_argument_at_index(argv):
    """
    Retrieves the value at the index specified in argv[1] from the argv array.

    Args:
        argv: A list of strings representing the command-line arguments.

    Returns:
        The value at the specified index, or None if an error occurs.
    """

    if len(argv) < 2:
        print("Error: Index argument missing.  Usage: script.py <index>")
        return None

    try:
        index = int(argv[1])  # Convert the index to an integer
    except ValueError:
        print("Error: Invalid index.  Index must be an integer.")
        return None

    if index < 0:
        print("Error: Index must be non-negative.")
        return None

    if index >= len(argv):
        print("Error: Index out of bounds.")
        return None

    return argv[index]


if __name__ == "__main__":
    result = get_argument_at_index(sys.argv)
    if result:
        print(f"Value at index {sys.argv[1]}: {result}")

