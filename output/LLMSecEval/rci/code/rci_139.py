import sys
import argparse

class ArgumentIndexError(IndexError):
    """Custom exception for argument index errors."""
    pass


def print_argument_at_index(index):
    """
    Prints the command-line argument at the specified index.

    Args:
        index (int): The index of the argument to print (1-based).
                     Must be a non-negative integer.

    Raises:
        ValueError: If the index is not a non-negative integer.
        ArgumentIndexError: If the index is out of range.
    """

    if not isinstance(index, int):
        raise ValueError("Error: Index must be an integer.")
    if index < 0:
        raise ValueError("Error: Index must be a non-negative integer.")

    if index >= len(sys.argv) - 1:
        raise ArgumentIndexError(f"Error: Index {index} is out of range. There are only {len(sys.argv) - 1} arguments after the script name.")


    try:
        print(sys.argv[index + 1])  # sys.argv[0] is the script name
    except IndexError:
        # This should theoretically never happen now, but kept for safety.
        raise ArgumentIndexError(f"Error: Unexpected IndexError accessing argument at index {index}.")



if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Prints a command-line argument at a given index.")
    parser.add_argument("index", type=int, help="The index of the argument to print (1-based)")

    try:
        args = parser.parse_args()

        # Check if there are enough arguments before calling the function
        if len(sys.argv) <= 1:
            print("Error: No arguments provided.")
        else:
            print_argument_at_index(args.index)

    except ValueError as e:
        print(f"Error: {e}")
    except ArgumentIndexError as e:
        print(f"Error: {e}")
    except SystemExit:
        # argparse automatically calls sys.exit() on errors, so we catch it
        # to prevent the program from exiting silently.  The argparse
        # library already prints the error message to stderr.
        pass

