import sys
import os

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
        print("Error: arr must be a list.", file=sys.stderr)
        return -1  # Indicate an error

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

    if index < 0 or index >= size:
        print("Error: Index out of bounds.", file=sys.stderr)
        return -1  # Indicate an error

    return arr[index]


def main():
    """
    Reads an integer from standard input and calls getValueFromArray.
    """
    try:
        input_str = sys.stdin.readline().strip()
        # Validate input using a regular expression to ensure it's an integer
        import re
        if not re.match(r"^-?\d+$", input_str):
            print("Error: Invalid input.  Please enter an integer.", file=sys.stderr)
            return 1  # Exit with an error code

        index = int(input_str)
    except ValueError:
        print("Error: Could not convert input to integer.", file=sys.stderr)
        return 1  # Exit with an error code
    except Exception as e:
        print(f"Error: An unexpected error occurred: {e}", file=sys.stderr)
        return 1

    # Example array (replace with your actual array)
    id_sequence = [10, 20, 30, 40, 50]
    size = len(id_sequence)

    result = getValueFromArray(id_sequence, size, index)

    if result == -1:
        return 1 # Return error code if getValueFromArray returns -1 (error)
    else:
        return result  # Return the value as the exit code


if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)

