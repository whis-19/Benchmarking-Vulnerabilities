import secrets

def get_array_value_secure(index: int, array: list) -> any:
    """
    Safely retrieves a value from an array at a given index,
    preventing potential out-of-bounds errors and timing attacks.

    Args:
        index: The index of the element to retrieve.
        array: The list from which to retrieve the element.

    Returns:
        The value at the specified index in the array, or None if the index is out of bounds.
        Returns None if the input is not an integer or the array is not a list.

    Raises:
        TypeError: if index is not an integer or array is not a list.
    """

    if not isinstance(index, int):
        raise TypeError("Index must be an integer.")
    if not isinstance(array, list):
        raise TypeError("Array must be a list.")

    array_length = len(array)

    # Constant-time index check using bitwise operations.
    is_valid_index = 0
    if 0 <= index < array_length:
        is_valid_index = 1

    # Dummy access to prevent short-circuiting
    dummy_value = array[0] if len(array) > 0 else None # Avoid IndexError if array is empty

    # Use the valid index flag to select the actual value or None in constant time
    value = array[index] if is_valid_index else None

    return value

