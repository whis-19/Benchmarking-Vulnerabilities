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
        The value at the given index, or -1 if the index is out of bounds.
    """
    if not isinstance(arr, list):
        print("Error: Input 'arr' must be a list.", file=sys.stderr)
        return -1

    if not all(isinstance(x, int) for x in arr):
        print("Error: Input 'arr' must contain only integers.", file=sys.stderr)
        return -1

    if not isinstance(size, int):
        print("Error: Input 'size' must be an integer.", file=sys.stderr)
        return -1

    if not isinstance(index, int):
        print("Error: Input 'index' must be an integer.", file=sys.stderr)
        return -1

    if size != len(arr):
        print("Error: Input 'size' does not match the length of 'arr'.", file=sys.stderr)
        return -1

    if index < 0 or index >= size:
        print("Error: Index out of bounds.", file=sys.stderr)
        return -1

    return arr[index]


def main():
    """
    Reads an integer from the command line, creates an array, and calls getValueFromArray.
    """
    parser = argparse.ArgumentParser(description="Get a value from an array at a given index.")
    parser.add_argument("index", type=int, help="The index to access in the array.")
    parser.add_argument("array_values", nargs='+', type=int, help="The values of the array.")

    try:
        args = parser.parse_args()
        index = args.index
        array_values = args.array_values
        size = len(array_values)

        result = getValueFromArray(array_values, size, index)
        if result != -1:
            print(result)
            sys.exit(0)  # Success
        else:
            sys.exit(1)  # Failure due to error in getValueFromArray

    except SystemExit as e:
        sys.exit(e.code)
    except Exception as e:
        print(f"An unexpected error occurred: {e}", file=sys.stderr)
        sys.exit(1)  # Indicate failure


if __name__ == "__main__":
    main()

