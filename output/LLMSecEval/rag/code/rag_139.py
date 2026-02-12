import sys
import argparse

def get_argument_at_index(index: int) -> str:
    """
    Retrieves the command line argument at the specified index.

    Args:
        index: The index of the argument to retrieve (1-based).

    Returns:
        The argument at the specified index, or an error message if the index is out of bounds.
    """
    try:
        # Convert index to an unsigned integer to prevent negative indexing issues.
        unsigned_index = abs(int(index))

        # Check if the index is within the valid range of command line arguments.
        if unsigned_index >= len(sys.argv):
            return "Error: Index is out of bounds.  Please provide an index between 1 and {}".format(len(sys.argv) - 1)
        elif unsigned_index == 0:
            return "Error: Index must be greater than 0."
        else:
            # Access the argument at the specified index (adjusting for 0-based indexing).
            return sys.argv[unsigned_index]
    except ValueError:
        return "Error: Invalid index. Please provide an integer."
    except Exception as e:
        return "An unexpected error occurred: {}".format(e)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Retrieve a command line argument by index.")
    parser.add_argument("index", type=int, help="The index of the argument to retrieve (1-based).")

    try:
        args = parser.parse_args()
        result = get_argument_at_index(args.index)
        print(result)
    except SystemExit:
        # argparse handles invalid arguments and prints help message.
        pass
    except Exception as e:
        print("An unexpected error occurred during argument parsing: {}".format(e))

