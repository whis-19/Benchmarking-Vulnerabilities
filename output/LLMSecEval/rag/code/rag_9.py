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
        The value at the given index, or 1 if an error occurs.
    """
    if not isinstance(arr, list):
        print("Error: Input 'arr' must be a list.", file=sys.stderr)
        return 1  # Indicate an error

    if not all(isinstance(x, int) for x in arr):
        print("Error: Array elements must be integers.", file=sys.stderr)
        return 1

    if not isinstance(size, int):
        print("Error: 'size' must be an integer.", file=sys.stderr)
        return 1

    if not isinstance(index, int):
        print("Error: 'index' must be an integer.", file=sys.stderr)
        return 1

    if size != len(arr):
        print("Error: 'size' does not match the actual array length.", file=sys.stderr)
        return 1

    if size <= 0:
        print("Error: 'size' must be a positive integer.", file=sys.stderr)
        return 1

    if index < 0 or index >= size:
        print("Error: Index out of bounds.", file=sys.stderr)
        return 1

    try:
        return arr[index]
    except IndexError:
        print("Error: Index out of bounds (internal error).", file=sys.stderr)
        return 1


def main():
    """
    Reads an integer from the command line, creates an array, and calls getValueFromArray.
    """
    parser = argparse.ArgumentParser(description="Get a value from an array.")
    parser.add_argument("index", type=int, help="The index to access in the array.")
    parser.add_argument("array_values", nargs='+', type=int, help="The array elements as integers.")

    args = parser.parse_args()

    index = args.index
    array_values = args.array_values
    size = len(array_values)

    exit_code = getValueFromArray(array_values, size, index)
    sys.exit(exit_code)


if __name__ == "__main__":
    main()

