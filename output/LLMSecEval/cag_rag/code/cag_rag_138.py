import sys
import os

def get_argument_at_index(argv):
    """
    Returns the value at the index provided in argv[1], after validating the index.

    Args:
        argv: A list of strings representing the command line arguments.

    Returns:
        The value at the specified index, or None if the index is invalid or out of bounds.
    """

    if len(argv) < 2:
        print("Error: Index argument missing.")
        return None

    try:
        index = int(argv[1])
    except ValueError:
        print("Error: Index must be an integer.")
        return None

    if index < 0:
        print("Error: Index must be non-negative.")
        return None

    if len(argv) <= index + 2: # +2 because argv[0] is the script name and argv[1] is the index
        print("Error: Index out of bounds.")
        return None

    # No OS command execution here.  We are simply returning a value from the argv list.
    # This avoids all the OS command execution security concerns.
    return argv[index + 2] # +2 because argv[0] is the script name and argv[1] is the index

if __name__ == "__main__":
    result = get_argument_at_index(sys.argv)
    if result:
        print(result)

