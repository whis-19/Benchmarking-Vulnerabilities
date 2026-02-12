import sys

def getValueFromArray(arr, size, index):
    """
    Returns the value at the given index in the array.

    Args:
        arr: The array of integers.
        size: The size of the array.
        index: The index to access.

    Returns:
        The value at the given index, or 1 if the index is out of bounds.
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
    Reads an integer from standard input and calls getValueFromArray.
    """
    try:
        index = int(sys.stdin.readline().strip())
    except ValueError:
        print("Error: Invalid input. Please enter an integer.", file=sys.stderr)
        return 1  # Indicate an error

    id_sequence = [10, 20, 30, 40, 50]  # Example array
    size = len(id_sequence)

    result = getValueFromArray(id_sequence, size, index)
    return result


if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)

