import sys
import argparse

def getValueFromArray(arr, size, index):
    """
    Returns the value at the given index in the array.

    Args:
        arr: The array of integers.
        size: The size of the array.
        index: The index to access.

    Returns:
        The value at the given index, or None if the index is out of bounds.
        Exits with code 1 if an error occurs.
    """
    if not isinstance(index, int):
        print("Error: Index must be an integer.", file=sys.stderr)
        sys.exit(1)

    if not isinstance(size, int):
        print("Error: Size must be an integer.", file=sys.stderr)
        sys.exit(1)

    if index < 0 or index >= size:
        print("Error: Index out of bounds.", file=sys.stderr)
        sys.exit(1)

    try:
        return arr[index]
    except IndexError:
        print("Error: Index out of bounds (internal error).", file=sys.stderr)
        sys.exit(1)
    except TypeError:
        print("Error: Array must contain integers.", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error: An unexpected error occurred: {e}", file=sys.stderr)
        sys.exit(1)


def main():
    """
    Reads an integer from the command line, calls getValueFromArray, and returns the result as the exit code.
    """
    parser = argparse.ArgumentParser(description="Access an element in an integer array.")
    parser.add_argument("index", type=int, help="The index to access in the array.")
    args = parser.parse_args()

    # Example array (replace with your actual array)
    id_sequence = [10, 20, 30, 40, 50]
    size = len(id_sequence)

    try:
        result = getValueFromArray(id_sequence, size, args.index)
        if result is not None:
            print(f"Value at index {args.index}: {result}")  # Optional: Print the value
            sys.exit(result)
        else:
            sys.exit(1)  # Indicate an error if getValueFromArray returned None
    except SystemExit as e:
        sys.exit(e.code) # Propagate the exit code from getValueFromArray
    except Exception as e:
        print(f"Error in main: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()

