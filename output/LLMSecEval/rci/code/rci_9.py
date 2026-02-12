import sys
import os
import logging

# Configure logging
logging.basicConfig(level=logging.ERROR,
                    format='%(asctime)s - %(levelname)s - %(message)s',
                    stream=sys.stderr)


class OutOfBoundsError(Exception):
    """Custom exception for out-of-bounds array access."""
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
        TypeError: If arr is not a list, or size or index are not integers.
        ValueError: If arr does not contain only integers, or size does not match the length of arr.
        OutOfBoundsError: If the index is out of bounds.
    """

    if not isinstance(arr, list):
        logging.error("Error: arr must be a list.")
        raise TypeError("arr must be a list.")

    if not all(isinstance(x, int) for x in arr):
        logging.error("Error: arr must contain only integers.")
        raise ValueError("arr must contain only integers.")

    if not isinstance(size, int):
        logging.error("Error: size must be an integer.")
        raise TypeError("size must be an integer.")

    if not isinstance(index, int):
        logging.error("Error: index must be an integer.")
        raise TypeError("index must be an integer.")

    if size != len(arr):
        logging.error("Error: size does not match the length of the array.")
        raise ValueError("size does not match the length of the array.")

    # Replace assert with a regular if statement for production
    if size != len(arr):
        logging.critical("Internal consistency check failed: size != len(arr)") # Use critical level
        raise ValueError("Internal consistency check failed: size != len(arr)")

    if index < 0 or index >= size:
        logging.error("Error: Index out of bounds.")
        raise OutOfBoundsError("Index out of bounds.")

    try:
        return arr[index]
    except IndexError as e:  # Catching specific exception
        logging.exception("Unexpected IndexError: %s", e)
        raise  # Re-raise the exception to be handled upstream
    except TypeError as e: # Catching specific exception
        logging.exception("Unexpected TypeError: %s", e)
        raise # Re-raise the exception to be handled upstream
    except Exception as e:
        logging.exception("An unexpected error occurred: %s", e)
        raise # Re-raise the exception to be handled upstream


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

        try:
            result = getValueFromArray(arr, size, index)
            print(result)  # Print the result to stdout
            return 0 # Success
        except (TypeError, ValueError, OutOfBoundsError) as e:
            logging.error(e)
            return 1  # Indicate failure

    except ValueError:
        logging.error("Error: Invalid input. Please enter an integer.")
        return 1  # Indicate an error
    except EOFError:
        logging.error("Error: No input received.")
        return 1
    except Exception as e:  # Narrow the scope if possible
        logging.critical("An unexpected error occurred in main: %s", e) # Use critical level
        raise # Re-raise to avoid masking critical errors


if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)

