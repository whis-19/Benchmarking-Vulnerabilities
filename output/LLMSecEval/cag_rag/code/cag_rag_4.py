import sys
import os

def print_argument_at_index(arguments):
    """
    Prints the string at the index specified by the second argument in the command line arguments.

    Args:
        arguments: A list of strings representing the command line arguments.
    """

    if len(arguments) < 3:
        print("Error: Not enough arguments provided.")
        return

    try:
        index = int(arguments[1])
    except ValueError:
        print("Error: Second argument must be an integer.")
        return

    if index < 0:
        print("Error: Index must be a non-negative integer.")
        return

    if index >= len(arguments):
        print("Error: Index is out of bounds.")
        return

    print(arguments[index])


if __name__ == "__main__":
    print_argument_at_index(sys.argv)

