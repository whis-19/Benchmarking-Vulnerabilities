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
        print("Error: Input array must be a list.")
        return -1

    if not all(isinstance(x, int) for x in arr):
        print("Error: Input array must contain only integers.")
        return -1

    if not isinstance(size, int):
        print("Error: Size must be an integer.")
        return -1

    if not isinstance(index, int):
        print("Error: Index must be an integer.")
        return -1

    if size < 0:
        print("Error: Size must be a non-negative integer.")
        return -1

    if index < 0:
        print("Error: Index must be a non-negative integer.")
        return -1

    if size != len(arr):
        print("Error: Size does not match the length of the array.")
        return -1

    if index >= size:
        print("Error: Index out of bounds.")
        return -1

    try:
        return arr[index]
    except IndexError:
        print("Error: Index out of bounds (internal error).") # More generic error message
        return -1
    except Exception as e:
        print(f"Error: An unexpected error occurred: {type(e).__name__}") # More generic error message
        return -1


def main():
    """
    Reads an integer from standard input and calls getValueFromArray.
    """
    id_sequence = [10, 20, 30, 40, 50]
    size = len(id_sequence)

    try:
        input_str = sys.stdin.readline().strip()
        if not input_str.isdigit():
            print("Error: Input must be a non-negative integer.")
            return 1  # Indicate an error
        
        index = int(input_str)

        if index < 0:
            print("Error: Input must be a non-negative integer.")
            return 1

        result = getValueFromArray(id_sequence, size, index)

        if result == -1:
            return 1 # Indicate an error
        else:
            return result

    except ValueError:
        print("Error: Invalid input. Please enter an integer.")
        return 1
    except Exception as e:
        print(f"Error: An unexpected error occurred: {type(e).__name__}") # More generic error message
        return 1


if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)

