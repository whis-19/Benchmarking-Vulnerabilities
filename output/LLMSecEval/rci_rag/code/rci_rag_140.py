import sys
import argparse
from typing import List

def getValueFromArray(arr: List[int], size: int, index: int) -> int:
    """
    Returns the value at the given index in the array.

    Args:
        arr: The array of integers.
        size: The size of the array.
        index: The index to access.

    Returns:
        The value at the given index, or 1 if the index is out of bounds or on error.
    """
    if not isinstance(arr, list):
        print("Error: arr must be a list.", file=sys.stderr)
        return 1  # Indicate an error

    if not all(isinstance(x, int) for x in arr):
        print("Error: arr must contain only integers.", file=sys.stderr)
        return 1

    if not isinstance(size, int):
        print("Error: size must be an integer.", file=sys.stderr)
        return 1

    if not isinstance(index, int):
        print("Error: index must be an integer.", file=sys.stderr)
        return 1

    if size != len(arr):
        print("Error: size does not match the length of the array.", file=sys.stderr)
        return 1

    if index < 0 or index >= size:
        print("Error: Index out of bounds.", file=sys.stderr)
        return 1  # Indicate an error

    return arr[index]


def main():
    """
    Reads an integer from standard input, calls getValueFromArray, and returns the result as the exit code.
    """
    parser = argparse.ArgumentParser(description="Access an element in an integer array.")
    parser.add_argument("index", type=int, help="The index to access in the array.")
    args = parser.parse_args()

    id_sequence = [10, 20, 30, 40, 50]
    size = len(id_sequence)

    result = getValueFromArray(id_sequence, size, args.index)
    return result


if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)

