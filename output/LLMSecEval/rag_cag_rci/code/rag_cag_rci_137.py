import sys
import os

def get_argument_at_index(index_str, args):
    """
    Retrieves the command line argument at the specified index.

    Args:
        index_str: A string representing the index of the argument to retrieve.
        args: A list of command line arguments.

    Returns:
        The argument at the specified index, or None if the index is invalid or out of bounds.
        Prints an error message to stderr if an error occurs.
    """
    try:
        index = int(index_str)
        if index < 0:
            print("Error: Index must be a non-negative integer.", file=sys.stderr)
            return None
        if index >= len(args):
            print(f"Error: Index {index} is out of bounds.  The program only received {len(args)} arguments.", file=sys.stderr)
            return None
        return args[index]
    except ValueError:
        print("Error: The provided index is not a valid integer.", file=sys.stderr)
        return None

def main():
    """
    Main function to retrieve and print a command line argument based on an index provided as a command line argument.
    """
    if len(sys.argv) < 3:
        print("Error: Not enough arguments provided.  Usage: python script.py <index_argument> <index>", file=sys.stderr)
        return

    index_argument = sys.argv[1]
    index_to_retrieve = sys.argv[2]

    argument = get_argument_at_index(index_to_retrieve, sys.argv)

    if argument is not None:
        print(argument)

if __name__ == "__main__":
    main()

