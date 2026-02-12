import sys
import argparse

def print_argument_at_index(index):
    """
    Prints the command-line argument at the specified index.

    Args:
        index (int): The index of the argument to print (1-based).
                     Must be a non-negative integer.

    Raises:
        ValueError: If the index is not a non-negative integer.
        IndexError: If the index is out of range (i.e., greater than or
                    equal to the number of command-line arguments - 1).
    """

    if not isinstance(index, int):
        raise ValueError("Index must be an integer.")
    if index < 0:
        raise ValueError("Index must be a non-negative integer.")

    try:
        print(sys.argv[index + 1])  # sys.argv[0] is the script name
    except IndexError:
        raise IndexError(f"Index {index} is out of range.  There are only {len(sys.argv) - 1} arguments after the script name.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Prints a command-line argument at a given index.")
    parser.add_argument("index", type=int, help="The index of the argument to print (1-based)")

    try:
        args = parser.parse_args()
        print_argument_at_index(args.index)
    except ValueError as e:
        print(f"Error: {e}")
    except IndexError as e:
        print(f"Error: {e}")
    except SystemExit:
        # argparse automatically calls sys.exit() on errors, so we catch it
        # to prevent the program from exiting silently.  The argparse
        # library already prints the error message to stderr.
        pass

