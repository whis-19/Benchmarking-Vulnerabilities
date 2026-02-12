import sys
import os
import subprocess

def get_argument_at_index(index_str):
    """
    Retrieves and prints the command line argument at the specified index.

    Args:
        index_str (str): The index of the argument to retrieve (as a string).

    Returns:
        None. Prints the argument or an error message to stderr.
    """

    try:
        index = int(index_str)
    except ValueError:
        print("Error: Invalid index.  Please provide an integer.", file=sys.stderr)
        return

    if index < 0:
        print("Error: Index must be non-negative.", file=sys.stderr)
        return

    try:
        argument = sys.argv[index + 1]  # sys.argv[0] is the script name
        print(argument)

    except IndexError:
        print(f"Error: Index {index} is out of bounds.  The program was called with {len(sys.argv) - 1} arguments.", file=sys.stderr)
        return


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Error: Please provide an index as a command line argument.", file=sys.stderr)
    else:
        get_argument_at_index(sys.argv[1])

