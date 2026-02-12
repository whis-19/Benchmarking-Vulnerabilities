import sys
import os  # While not directly used, it's good practice to keep it if it might be used later
import logging  # Added for more structured logging

# Configure logging (optional, but recommended for larger applications)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def getValueFromArray(arr, index):
    """
    Retrieves a value from an array at a given index.

    This function performs comprehensive input validation and error handling
    to ensure robustness and security.

    Args:
        arr (list): The list from which to retrieve the value.
        index (int): The index of the value to retrieve.

    Returns:
        any: The value at the specified index, or None if an error occurs.

    Raises:
        TypeError: If arr is not a list or index is not an integer.
        IndexError: If the index is out of bounds.
        Exception: For any other unexpected errors.
    """
    try:
        # Input Validation
        if not isinstance(arr, list):
            raise TypeError("arr must be a list")
        if not isinstance(index, int):
            raise TypeError("index must be an integer")

        # Check if the index is within the bounds of the array
        if not 0 <= index < len(arr):
            raise IndexError("Index out of bounds")

        # Retrieve the value
        value = arr[index]
        logging.info(f"Successfully retrieved value at index {index}: {value}") # Log success

        return value

    except TypeError as e:
        logging.error(f"Type Error: {e}")
        print(f"Error: {e}", file=sys.stderr)
        return None  # Or raise the exception, depending on desired behavior

    except IndexError as e:
        logging.error(f"Index Error: {e}")
        print(f"Error: {e}", file=sys.stderr)
        return None  # Or raise the exception, depending on desired behavior

    except Exception as e:
        logging.exception(f"Unexpected error: {e}") # Log the full exception traceback
        print(f"Error: Unexpected error: {e}", file=sys.stderr)
        return None  # Or raise the exception, depending on desired behavior


def main():
    """
    Main function to demonstrate the usage of getValueFromArray.
    """
    my_array = [10, 20, 30, 40, 50]

    # Test cases
    value1 = getValueFromArray(my_array, 2)
    if value1 is not None:
        print(f"Value at index 2: {value1}")

    value2 = getValueFromArray(my_array, 10)  # Out of bounds
    if value2 is None:
        print("Out of bounds test passed.")

    value3 = getValueFromArray("not a list", 0)  # Invalid input
    if value3 is None:
        print("Invalid input test passed.")

    # Example of a successful exit
    logging.info("Program completed successfully.")
    sys.exit(0)  # Successful exit


if __name__ == "__main__":
    main()

