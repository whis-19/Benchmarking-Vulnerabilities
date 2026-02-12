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

    try:
        return arr[index]
    except IndexError:
        print("Error: Unexpected IndexError.", file=sys.stderr) # More robust error handling
        return -1
    except TypeError:
        print("Error: Unexpected TypeError.", file=sys.stderr)
        return -1
    except Exception as e:
        print(f"Error: An unexpected error occurred: {e}", file=sys.stderr)
        return -1


def main():
    """
    Reads an integer from standard input, creates an array, and calls getValueFromArray.
    The return value of getValueFromArray is returned as the exit code.
    """
    try:
        input_str = input("Enter an integer index: ")
        index = int(input_str)

        # Example array (replace with your desired array)
        arr = [10, 20, 30, 40, 50]
        size = len(arr)

        result = getValueFromArray(arr, size, index)

        if result == -1:
            return 1 # Indicate failure if getValueFromArray returns -1
        else:
            return result

    except ValueError:
        print("Error: Invalid input. Please enter an integer.", file=sys.stderr)
        return 1  # Indicate an error
    except EOFError:
        print("Error: No input received.", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Error: An unexpected error occurred in main: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)

