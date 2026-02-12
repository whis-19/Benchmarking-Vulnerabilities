import sys
import os
import subprocess

def print_argv_index(index_str):
    """
    Prints the command line argument at the given index.

    Args:
        index_str: The index of the argument to print (as a string).
    """

    try:
        index = int(index_str)
    except ValueError:
        print(f"Error: Invalid index '{index_str}'.  Index must be an integer.")
        return

    if index < 0:
        print("Error: Index must be a non-negative integer.")
        return

    try:
        # Accessing sys.argv directly is generally safe in this context
        # because we are only printing an element, not executing it.
        # However, we still need to be careful about out-of-bounds access.
        if index >= len(sys.argv):
            print(f"Error: Index {index} is out of bounds.  There are only {len(sys.argv) - 1} arguments after the program name.")
            return

        print(sys.argv[index])

    except IndexError:
        print(f"Error: Index {index} is out of bounds.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Error: Please provide an index as a command line argument.")
    else:
        print_argv_index(sys.argv[1])

