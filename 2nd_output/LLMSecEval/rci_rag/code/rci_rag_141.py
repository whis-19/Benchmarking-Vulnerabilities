import sys
import re
import logging

# Configure logging (optional, but recommended for production)
logging.basicConfig(level=logging.ERROR,  # Or logging.DEBUG for more detailed logs
                    format='%(asctime)s - %(levelname)s - %(message)s')


INTEGER_REGEX = r"^-?\d+$"
MAX_ARRAY_SIZE = 1000  # Example limit for user-supplied arrays


def getValueFromArray(arr, size, index):
    """
    Returns the value at the given index in the array.  Raises IndexError if out of bounds.
    Raises TypeError if input types are incorrect.
    Raises ValueError if size does not match array length.

    Args:
        arr: The array of integers.
        size: The size of the array.
        index: The index to access.

    Returns:
        The value at the given index.

    Raises:
        TypeError: If input types are incorrect.
        ValueError: If size does not match array length.
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
        1: Invalid input format or type error.
        2: Index out of bounds.
        3: Other unexpected error.
    """
    try:
        input_str = sys.stdin.readline().strip()

        # Validate input using a regular expression to ensure it's an integer
        if not re.match(INTEGER_REGEX, input_str):
            print("Error: Invalid input. Please enter an integer.", file=sys.stderr)
            return 1  # Indicate an error

        index = int(input_str)

        # Example array (replace with your actual array)
        # id_sequence = [10, 20, 30, 40, 50]  # Hardcoded for now
        # size = len(id_sequence)

        # Example of how to handle user-supplied array (if needed)
        id_sequence_str = sys.stdin.readline().strip()
        try:
            id_sequence = [int(x) for x in id_sequence_str.split(",")] # Example: "10,20,30,40,50"
        except ValueError:
            print("Error: Array contains non-integer elements.", file=sys.stderr)
            return 1

        if len(id_sequence) > MAX_ARRAY_SIZE:
            print("Error: Array size exceeds maximum allowed.", file=sys.stderr)
            return 1
        size = len(id_sequence)
        # for element in id_sequence: #Already validated in the list comprehension above
        #     if not isinstance(element, int):
        #         print("Error: Array contains non-integer elements.", file=sys.stderr)
        #         return 1


        # Range check on index
        if index < -1000 or index > 1000:
            print("Error: Input integer is out of the acceptable range.", file=sys.stderr)
            return 1

        result = getValueFromArray(id_sequence, size, index)
        return result

    except ValueError as e:
        print("Error: Invalid input. See logs for details.", file=sys.stderr)
        logging.error(f"ValueError: {e}")
        return 1
    except TypeError as e:
        print("Error: Invalid input. See logs for details.", file=sys.stderr)
        logging.error(f"TypeError: {e}")
        return 1
    except IndexError as e:
        print("Error: Index out of bounds.", file=sys.stderr)
        logging.error(f"IndexError: {e}")
        return 2  # Specific error code for index out of bounds
    except Exception as e:
        print("An unexpected error occurred. See logs for details.", file=sys.stderr)
        logging.exception(e)  # Log the full exception traceback
        return 3  # Indicate an error


if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)

