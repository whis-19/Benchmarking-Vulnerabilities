import sys
import re

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
        print("Error: arr must be a list.")
        return 1
    
    if not all(isinstance(x, int) for x in arr):
        print("Error: arr must contain only integers.")
        return 1

    if not isinstance(size, int):
        print("Error: size must be an integer.")
        return 1

    if not isinstance(index, int):
        print("Error: index must be an integer.")
        return 1

    if size != len(arr):
        print("Error: size does not match the length of the array.")
        return 1

    if size <= 0:
        print("Error: size must be a positive integer.")
        return 1

    if index < 0 or index >= size:
        print("Error: Index out of bounds.")
        return 1

    return arr[index]


def main():
    """
    Reads an integer from standard input, creates an array, and calls getValueFromArray.
    The return value of getValueFromArray is returned as the exit code.
    """
    try:
        input_str = sys.stdin.readline().strip()

        # Validate input using a regular expression to ensure it's an integer
        if not re.match(r"^-?\d+$", input_str):
            print("Error: Invalid input. Please enter an integer.")
            return 1

        index = int(input_str)

        # Example array (replace with your desired array)
        arr = [10, 20, 30, 40, 50]
        size = len(arr)

        result = getValueFromArray(arr, size, index)
        return result

    except ValueError:
        print("Error: Could not convert input to an integer.")
        return 1
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return 1


if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)

