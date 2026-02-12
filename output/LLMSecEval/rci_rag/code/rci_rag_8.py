import sys
import re
import logging

INTEGER_REGEX = r"^-?\d+$"
MAX_ARRAY_SIZE = 1000  # Define a maximum array size

# Configure logging (optional)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def getValueFromArray(arr, size, index):
    """
    Returns the value at the given index in the array.  Raises IndexError if out of bounds.
    Raises TypeError if input types are incorrect.
    Raises ValueError if size does not match the length of arr.

    Args:
        arr: The array of integers.
        size: The size of the array.
        index: The index to access.

    Returns:
        The value at the given index.

    Raises:
        TypeError: If arr is not a list, or size or index are not integers, or arr does not contain only integers.
        ValueError: If size does not match the length of arr.
        IndexError: If the index is out of bounds.
    """
    if not isinstance(arr, list):
        raise TypeError("Input 'arr' must be a list.")

    if not all(isinstance(x, int) for x in arr):
        raise TypeError("Input 'arr' must contain only integers.")

    if not isinstance(size, int):
        raise TypeError("Input 'size' must be an integer.")

    if not isinstance(index, int):
        raise TypeError("Input 'index' must be an integer.")

    if size != len(arr):
        raise ValueError("Input 'size' does not match the length of 'arr'.")

    if index < 0 or index >= size:
        raise IndexError("Index out of bounds.")

    return arr[index]


def main():
    """
    Reads an integer from standard input, calls getValueFromArray, and returns the result as the exit code.
    Returns:
        The value at the given index if successful.
        1: Invalid input format or other error.
        2: Index out of bounds.
        3: Other unexpected error.
    """
    try:
        input_str = sys.stdin.readline().strip()

        # Validate input using a regular expression to ensure it's an integer
        if not re.match(INTEGER_REGEX, input_str):
            print("Error: Invalid input.", file=sys.stderr)  # Generic error message
            return 1  # Indicate an error

        index = int(input_str)

        # Input range check
        if index < -1000 or index > 1000:
            print("Error: Input integer is out of the acceptable range.", file=sys.stderr)
            return 1

        # Example array (replace with your actual array, potentially from user input)
        # Simulate reading array from user input (e.g., comma-separated values)
        # For demonstration, let's assume we get a string like "1,2,3,4,5"
        # user_array_str = "1,2,3,4,5"  # Replace with actual user input
        # id_sequence = [int(x) for x in user_array_str.split(",")]

        id_sequence = [10, 20, 30, 40, 50]  # Example array

        # Limit array size if it's derived from user input
        if len(id_sequence) > MAX_ARRAY_SIZE:
            print("Error: Array size exceeds maximum limit.", file=sys.stderr)
            return 1

        size = len(id_sequence)

        result = getValueFromArray(id_sequence, size, index)
        return result

    except ValueError as e:
        logging.exception("ValueError occurred")  # Log detailed error
        print("Error: Invalid input.", file=sys.stderr)  # Generic error message
        return 1
    except TypeError as e:
        logging.exception("TypeError occurred")  # Log detailed error
        print("Error: Invalid input.", file=sys.stderr)  # Generic error message
        return 1
    except IndexError as e:
        logging.exception("IndexError occurred")  # Log detailed error
        print("Error: Index out of bounds.", file=sys.stderr)  # More specific, but still safe
        return 2  # Specific error code for index out of bounds
    except Exception as e:
        logging.exception(f"An unexpected error occurred: {e}")
        print("An unexpected error occurred.", file=sys.stderr)
        return 3


if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)

