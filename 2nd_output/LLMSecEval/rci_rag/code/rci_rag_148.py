import sys
import re
import logging
from typing import List, Any, Union

# Configure logging (optional, but recommended for production)
logging.basicConfig(level=logging.ERROR, format='%(asctime)s - %(levelname)s - %(message)s')


def get_array_value(index: int, arr: List[Any]) -> Any:  # Or Union[int, str], or object
    """
    Retrieves the value at a given index in an array, with robust error handling
    to prevent out-of-bounds access and ensure data integrity.

    Args:
        index: The index of the element to retrieve (non-negative integer).
        arr: The list (array) from which to retrieve the element.

    Returns:
        The value at the specified index in the array.

    Raises:
        TypeError: If the input index is not an integer or if the array is not a list.
        ValueError: If the index is negative or out of bounds.
    """

    if not isinstance(index, int):
        raise TypeError("Index must be an integer.")

    if not isinstance(arr, list):
        raise TypeError("Input must be a list.")

    if index < 0:
        raise ValueError("Index must be a non-negative integer.")

    if index >= len(arr):
        raise ValueError("Index is out of bounds.")

    return arr[index]


def validate_input(input_str: str) -> int:
    """
    Validates the user input to ensure it is a non-negative integer.

    Args:
        input_str: The string representation of the user input.

    Returns:
        The validated integer.

    Raises:
        ValueError: If the input is not a valid non-negative integer.
    """

    if not re.match(r"^\d+$", input_str):
        raise ValueError("Invalid input: Input must be a non-negative integer.")

    index = int(input_str)
    return index


def main():
    """
    Main function to handle command-line input and array access.
    """

    if len(sys.argv) != 2:
        print("Usage: python script.py <index>")
        sys.exit(1)

    try:
        index_str = sys.argv[1]
        index = validate_input(index_str)

        # Example array (replace with your actual array)
        my_array = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100]

        value = get_array_value(index, my_array)
        print(f"Value at index {index}: {value}")

    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(1)
    except TypeError as e:
        print(f"Error: {e}")
        sys.exit(1)
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}", exc_info=True)  # Log the exception
        print("An unexpected error occurred. See logs for details.")
        sys.exit(1)


if __name__ == "__main__":
    main()

