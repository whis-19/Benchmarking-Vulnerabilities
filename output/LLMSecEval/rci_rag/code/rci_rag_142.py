import sys
import argparse

MAX_INT = sys.maxsize
MAX_ARRAY_SIZE = 1000

def getValueFromArray(arr, size, index):
    """
    Returns the value at the given index in the array.

    Args:
        arr: The array of integers.
        size: The size of the array.
        index: The index to access.

    Returns:
        The value at the given index, or None if the index is out of bounds.
    """
    if not isinstance(arr, list):
        print("Error: Invalid input - array must be a list.", file=sys.stderr)
        return None

    if not all(isinstance(x, int) for x in arr):
        print("Error: Invalid input - array elements must be integers.", file=sys.stderr)
        return None

    if not isinstance(size, int):
        print("Error: Invalid input - size must be an integer.", file=sys.stderr)
        return None

    if not isinstance(index, int):
        print("Error: Invalid input - index must be an integer.", file=sys.stderr)
        return None

    if size < 0 or size > MAX_INT:
        print("Error: Invalid input - size out of range.", file=sys.stderr)
        return None

    if index < 0 or index > MAX_INT:
        print("Error: Invalid input - index out of range.", file=sys.stderr)
        return None

    if size != len(arr):
        print("Error: Invalid input - size does not match array length.", file=sys.stderr)
        return None

    if index >= size:
        print("Error: Index out of bounds.", file=sys.stderr)
        return None

    return arr[index]


def main():
    """
    Reads an integer from the standard input, calls getValueFromArray,
    and returns the return value of getValueFromArray as the exit code.
    """
    parser = argparse.ArgumentParser(description="Get a value from an array.")
    parser.add_argument("index", type=int, help="The index to access in the array.")
    parser.add_argument("array_values", nargs='+', type=int, help="The array values as integers.")

    try:
        args = parser.parse_args()
        index = args.index
        arr = args.array_values

        if len(arr) > MAX_ARRAY_SIZE:
            print("Error: Array size exceeds the maximum allowed.", file=sys.stderr)
            sys.exit(1)

        size = len(arr)

        result = getValueFromArray(arr, size, index)

        if result is not None:
            print(result)
            sys.exit(0)  # Success
        else:
            sys.exit(1)  # Failure

    except SystemExit as e:
        sys.exit(e.code)
    except Exception as e:
        print("Error: An unexpected error occurred.", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()

