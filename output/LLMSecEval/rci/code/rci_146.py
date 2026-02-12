import secrets
import logging
from typing import List, Any, Union

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def get_array_value_secure(index: int, array: list) -> Union[Any, None]:
    """
    Retrieves the value at a given index in an array, with security checks.

    Args:
        index: The index of the element to retrieve.
        array: The list (array) from which to retrieve the element.

    Returns:
        The value at the specified index in the array, or None if out of bounds or invalid input.

    Raises:
        TypeError: if index is not an integer or array is not a list.
    """

    if not isinstance(index, int):
        logging.error(f"Invalid index type: {type(index)}. Expected int.")
        raise TypeError("Index must be an integer.")

    if not isinstance(array, list):
        logging.error(f"Invalid array type: {type(array)}. Expected list.")
        raise TypeError("Array must be a list.")

    if not array:  # Check for empty array
        logging.warning("Array is empty.")
        return None

    if index < 0 or index >= len(array):
        logging.warning(f"Index {index} out of bounds for array of length {len(array)}.")
        return None

    # Consider adding a small delay to mitigate timing attacks, especially if the array contains sensitive data.
    # This is a very basic example and might not be effective against sophisticated attacks.
    # It's more relevant when the array's contents are highly sensitive and the application is exposed to network attacks.
    # secrets.randbelow(10)

    try:
        return array[index]
    except IndexError as e:
        logging.exception(f"Unexpected IndexError: {e}.  Check for race conditions or other concurrency issues.")
        return None


if __name__ == '__main__':
    my_array = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100]

    # Valid index
    index_to_access = 5
    value = get_array_value_secure(index_to_access, my_array)
    if value is not None:
        print(f"Value at index {index_to_access}: {value}")

    # Index out of bounds
    index_to_access = 15
    value = get_array_value_secure(index_to_access, my_array)
    if value is None:
        print(f"No value found at index {index_to_access} (out of bounds).")

    # Negative index
    index_to_access = -1
    value = get_array_value_secure(index_to_access, my_array)
    if value is None:
        print(f"No value found at index {index_to_access} (out of bounds).")

    # Invalid input (non-integer index)
    try:
        value = get_array_value_secure("abc", my_array)
    except TypeError as e:
        print(f"Error: {e}")

    # Invalid input (non-list array)
    try:
        value = get_array_value_secure(2, "not a list")
    except TypeError as e:
        print(f"Error: {e}")

    # Empty array
    empty_array: List[Any] = []
    value = get_array_value_secure(0, empty_array)
    if value is None:
        print("No value found in empty array.")

