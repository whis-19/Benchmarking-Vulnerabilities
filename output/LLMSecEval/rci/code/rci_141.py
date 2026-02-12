import sys
import os
from typing import List, Optional, Union

def getValueFromArray(arr: List[int], size: int, index: Union[int, str]) -> Optional[int]:
    """
    Retrieves a value from an array at a given index, with bounds checking and sanitization.

    Args:
        arr: The array of integers.
        size: The size of the array.
        index: The index to access (can be an integer or a string representation of an integer).

    Returns:
        The value at the given index if the index is valid, otherwise None.
        Raises TypeError, ValueError, or IndexError if an error occurs.
    """

    # Type checking and sanitization
    if not isinstance(arr, list):
        raise TypeError("arr must be a list.")

    if not all(isinstance(x, int) for x in arr):
        raise TypeError("arr must contain only integers.")

    if not isinstance(size, int):
        raise TypeError("size must be an integer.")

    if not isinstance(index, (int, str)):
        raise TypeError("index must be an integer or a string representation of an integer.")

    try:
        index = int(index)  # Convert index to integer, sanitizing string input
    except ValueError:
        raise ValueError("index must be a valid integer.")

    if size != len(arr):
        raise ValueError("size does not match the length of the array.")

    # Input Sanitization (Defense in Depth - Limit index range)
    MAX_ARRAY_SIZE = 1000  # Example limit to prevent potential DoS
    if size > MAX_ARRAY_SIZE:
        raise ValueError(f"Array size exceeds maximum allowed size of {MAX_ARRAY_SIZE}.")

    if index < 0 or index >= size:
        raise IndexError("Index out of bounds.")

    try:
        return arr[index]
    except IndexError as e:  # Handle potential unexpected IndexError (shouldn't happen)
        print(f"Unexpected IndexError: {e}", file=sys.stderr) # Log the error
        return None # Or re-raise the exception if appropriate


def main():
    """
    Reads an integer from standard input, calls getValueFromArray, and returns the result as the exit code.
    """
    id_sequence = [10, 20, 30, 40, 50]
    size = len(id_sequence)

    try:
        input_str = input("Enter an index: ")
        index = input_str  # Pass the input string directly to getValueFromArray
    except ValueError:
        print("Error: Invalid input. Please enter an integer.", file=sys.stderr)
        return 1  # Indicate an error

    try:
        result = getValueFromArray(id_sequence, size, index)
        if result is not None:
            print(result)  # Print the result to standard output
            return 0  # Return 0 for success
        else:
            return 1 # Indicate an error in getValueFromArray
    except (TypeError, ValueError, IndexError) as e:
        print(f"Error: {e}", file=sys.stderr) # Log the error message
        return 1


if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)

