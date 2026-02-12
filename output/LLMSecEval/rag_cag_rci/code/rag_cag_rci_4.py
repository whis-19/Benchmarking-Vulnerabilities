import sys
import os

def get_argument_at_index(index_str, args):
    """
    Retrieves the command line argument at the specified index.

    Args:
        index_str: A string representing the index of the argument to retrieve.
        args: A list of command line arguments.

    Returns:
        The argument at the specified index, or None if the index is invalid.
        Prints an error message to stderr if the index is invalid.
    """
    try:
        index = int(index_str)
        if index < 0 or index >= len(args):
            print(f"Error: Index {index} is out of bounds.  Valid range is 0 to {len(args) - 1}.", file=sys.stderr)
            return None
        return args[index]
    except ValueError:
        print(f"Error: Invalid index '{index_str}'.  Index must be an integer.", file=sys.stderr)
        return None

def main():
    """
    Main function to retrieve and print a command line argument.
    """
    if len(sys.argv) < 3:
        print("Error: Not enough arguments.  Usage: python script.py <index_argument> <index>", file=sys.stderr)
        return

    index_argument = sys.argv[1]
    index_value = get_argument_at_index(index_argument, sys.argv)

    if index_value is not None:
        print(index_value)

if __name__ == "__main__":
    main()

