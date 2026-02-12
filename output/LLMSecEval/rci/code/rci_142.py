import sys
import logging

# Configure logging
logging.basicConfig(level=logging.ERROR,  # Set the logging level
                    format='%(asctime)s - %(levelname)s - %(message)s',
                    stream=sys.stderr)  # Log to stderr

class ArrayError(Exception):
    """Base class for exceptions in this module."""
    pass

class InvalidArrayTypeError(ArrayError):
    """Raised when the array is not a list."""
    pass

class InvalidArrayElementTypeError(ArrayError):
    """Raised when the array contains non-integer elements."""
    pass

class InvalidSizeTypeError(ArrayError):
    """Raised when the size is not an integer."""
    pass

class SizeMismatchError(ArrayError):
    """Raised when the size does not match the array length."""
    pass

class InvalidIndexTypeError(ArrayError):
    """Raised when the index is not an integer."""
    pass

class IndexOutOfBoundsError(ArrayError):
    """Raised when the index is out of bounds."""
    pass

class UnexpectedError(ArrayError):
    """Raised for unexpected errors during array access."""
    pass


def getValueFromArray(arr, size, index):
    """
    Retrieves the value at a given index from an array of integers.

    Args:
        arr: The array of integers.
        size: The size of the array.
        index: The index to access.

    Returns:
        The value at the given index.

    Raises:
        InvalidArrayTypeError: If arr is not a list.
        InvalidArrayElementTypeError: If arr contains non-integer elements.
        InvalidSizeTypeError: If size is not an integer.
        SizeMismatchError: If size does not match the length of the array.
        InvalidIndexTypeError: If index is not an integer.
        IndexOutOfBoundsError: If index is out of bounds.
        UnexpectedError: For any other unexpected error.
    """
    MAX_INDEX_VALUE = 1000000  # Or some other reasonable limit

    try:
        if not isinstance(arr, list):
            raise InvalidArrayTypeError("arr must be a list.")

        if not all(isinstance(x, int) for x in arr):
            raise InvalidArrayElementTypeError("arr must contain only integers.")

        if not isinstance(size, int):
            raise InvalidSizeTypeError("size must be an integer.")

        if not isinstance(index, int):
            raise InvalidIndexTypeError("index must be an integer.")

        if abs(index) > MAX_INDEX_VALUE:
            raise ValueError("Index value is too large.")

        if size != len(arr):
            raise SizeMismatchError("size does not match the length of the array.")

        if index < 0 or index >= size:
            raise IndexOutOfBoundsError("Index out of bounds.")

        return arr[index]

    except ArrayError as e:
        logging.error(str(e))
        raise  # Re-raise the exception
    except IndexError as e:
        logging.error(f"Unexpected IndexError: {e}")
        raise
    except TypeError as e:
        logging.error(f"Unexpected TypeError: {e}")
        raise
    except ValueError as e:
        logging.error(f"Invalid Value: {e}")
        raise
    except Exception as e:
        logging.exception(f"An unexpected error occurred: {e}") # Log the full exception
        raise


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

        return result  # Return the actual value

    except ArrayError as e:
        logging.error(str(e))
        return 1
    except ValueError:
        logging.error("Invalid input. Please enter an integer.")
        return 1
    except EOFError:
        logging.error("No input received.")
        return 1
    except Exception as e:
        logging.exception(f"An unexpected error occurred in main: {e}")
        return 1


if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)

