import sys
import os

def getValueFromArray(arr, size, index):
    """
    Retrieves a value from an array at a given index, with bounds checking.

    Args:
        arr: The array of integers.
        size: The size of the array.
        index: The index to access.

    Returns:
        The value at the given index if the index is valid, otherwise returns -1 and prints an error message to stderr.
    """
    if not isinstance(arr, list):
        print("Error: arr must be a list.", file=sys.stderr)
        return -1

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
        return -1
    
    try:
        return arr[index]
    except IndexError:  # Handle potential unexpected IndexError
        print("Error: Unexpected IndexError.", file=sys.stderr)
        return -1


def main():
    """
    Reads an integer from standard input, creates an array, and calls getValueFromArray.
    The return value of getValueFromArray is returned as the exit code.
    """
    try:
        n = int(input())  # Read the size of the array
        if n <= 0:
            print("Error: Array size must be positive.", file=sys.stderr)
            return 1  # Indicate an error

        # Create an array of integers (example: filled with zeros)
        arr = [0] * n  # Initialize with zeros.  Important to initialize.

        # Populate the array (example: read values from input)
        for i in range(n):
            try:
                arr[i] = int(input()) # Read each element from input
            except ValueError:
                print("Error: Invalid input for array element. Must be an integer.", file=sys.stderr)
                return 1 # Indicate an error

        index = int(input())  # Read the index from standard input

        result = getValueFromArray(arr, n, index)
        return result  # Return the result as the exit code

    except ValueError:
        print("Error: Invalid input. Must be an integer.", file=sys.stderr)
        return 1  # Indicate an error
    except EOFError:
        print("Error: Unexpected end of input.", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"An unexpected error occurred: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)

