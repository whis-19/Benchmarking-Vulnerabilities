import sys

def getValueFromArray(arr, size, index):
    """
    Returns the value at the given index in the array.
    Handles potential out-of-bounds access.

    Args:
        arr: The array of integers.
        size: The size of the array.
        index: The index to access.

    Returns:
        The value at the given index, or 1 if the index is out of bounds.
    """
    if not isinstance(index, int):
        print("Error: Index must be an integer.", file=sys.stderr)
        return 1  # Indicate an error

    if not isinstance(size, int):
        print("Error: Size must be an integer.", file=sys.stderr)
        return 1

    if index < 0 or index >= size:
        print("Error: Index out of bounds.", file=sys.stderr)
        return 1  # Indicate an error
    try:
        return arr[index]
    except TypeError as e:
        print(f"Error: Array element is not an integer: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"An unexpected error occurred: {e}", file=sys.stderr)
        return 1


def main():
    """
    Reads an integer from standard input, calls getValueFromArray,
    and returns the result as the exit code.
    """
    id_sequence = [10, 20, 30, 40, 50]
    size = len(id_sequence)

    try:
        input_str = sys.stdin.readline().strip()
        index = int(input_str)
    except ValueError:
        print("Error: Invalid input. Please enter an integer.", file=sys.stderr)
        return 1  # Indicate an error
    except Exception as e:
        print(f"An unexpected error occurred during input: {e}", file=sys.stderr)
        return 1

    result = getValueFromArray(id_sequence, size, index)
    return result


if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)

