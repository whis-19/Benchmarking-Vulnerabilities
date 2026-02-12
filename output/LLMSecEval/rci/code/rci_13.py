import logging
from typing import List, Any, Optional, Union

logging.basicConfig(level=logging.WARNING)  # Configure logging

def get_array_value_secure(index: int, array: List[Any]) -> Optional[Any]:
    """
    Retrieves the value at a given index in an array, with security checks.

    Args:
        index: The index of the element to retrieve.
        array: The list (array) from which to retrieve the element.

    Returns:
        The value at the specified index in the array.
        Returns None if the index is out of bounds or if the input is invalid.

    Raises:
        TypeError: if index is not an integer or array is not a list.
    """

    if not isinstance(index, int):
        raise TypeError("Index must be an integer.")

    if not isinstance(array, list):
        raise TypeError("Array must be a list.")

    if index < 0 or index >= len(array):
        logging.warning("Index out of bounds.")  # Log a generic message
        return None

    return array[index]


# Example usage:
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

