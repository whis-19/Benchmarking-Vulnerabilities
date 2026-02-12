import sys
import os

def getValueFromArray(arr, size, index):
    """
    Retrieves the value at a given index from an array of integers.

    Args:
        arr: The array of integers.
        size: The size of the array.
        index: The index to access.

    Returns:
        The value at the given index, or -1 if the index is out of bounds.
    """
    if not isinstance(arr, list):
        print("Error: arr must be a list.", file=sys.stderr)
        return -1  # Or raise an exception if appropriate

    if not all(isinstance(x, int) for x in arr):
        print("Error: arr must contain only integers.", file=sys.stderr)
        return -1

    if not isinstance(size, int):
        print("Error: size must be an integer.", file=sys.stderr)
        return -1

    if not isinstance(index, int):
        print("Error: index must be an integer.", file=sys.stderr)
        return -1

    if size != len(arr):
        print("Error: size does not match the length of the array.", file=sys.stderr)
        return -1

    if 0 <= index < size:
        return arr[index]
    else:
        print("Error: Index out of bounds.", file=sys.stderr)
        return -1


def main():
    """
    Reads an integer from standard input, calls getValueFromArray, and returns the result as the exit code.
    """
    id_sequence = [10, 20, 30, 40, 50]
    size = len(id_sequence)

    try:
        index = int(input())
    except ValueError:
        print("Error: Invalid input. Please enter an integer.", file=sys.stderr)
        return 1  # Indicate an error

    result = getValueFromArray(id_sequence, size, index)

    if result == -1:
        return 1 # Indicate an error in getValueFromArray
    else:
        return result


if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)

