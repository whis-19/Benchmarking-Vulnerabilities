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
        The value at the given index, or 1 if an error occurs.
    """
    if not isinstance(arr, list):
        print("Error: Input array must be a list.")
        return 1  # Indicate an error

    if not all(isinstance(x, int) for x in arr):
        print("Error: Array elements must be integers.")
        return 1

    if not isinstance(size, int):
        print("Error: Size must be an integer.")
        return 1

    if not isinstance(index, int):
        print("Error: Index must be an integer.")
        return 1

    if size != len(arr):
        print("Error: Size does not match the array length.")
        return 1

    if index < 0 or index >= size:
        print("Error: Index out of bounds.")
        return 1  # Indicate an error

    try:
        return arr[index]
    except IndexError:
        print("Error: Index out of bounds (internal error).") # More specific error message
        return 1 # Indicate an error


def main():
    """
    Reads an integer from standard input, calls getValueFromArray, and returns the result as the exit code.
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
            print("Error: Index must be a non-negative integer.")
            return 1

    except ValueError:
        print("Error: Invalid input. Please enter an integer.")
        return 1  # Indicate an error
    except Exception as e:
        print(f"Error: An unexpected error occurred: {e}")
        return 1

    result = getValueFromArray(id_sequence, size, index)
    return result  # Return the result as the exit code


if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)

