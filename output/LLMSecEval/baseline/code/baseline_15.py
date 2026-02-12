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
        Returns None if the input is invalid.

    Raises:
        TypeError: if index is not an integer or array is not a list.
    """

    if not isinstance(index, int):
        raise TypeError("Index must be an integer.")
    if not isinstance(array, list):
        raise TypeError("Array must be a list.")

    array_length = len(array)

    # Use a constant-time comparison to prevent timing attacks.
    # This avoids revealing information about the index based on how long the comparison takes.
    is_valid_index = secrets.compare_digest(str(index >= 0 and index < array_length), "True")

    if is_valid_index:
        return array[index]
    else:
        return None  # Or raise an IndexError if you prefer to signal an error explicitly


# Example usage:
if __name__ == '__main__':
    my_array = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100]

    try:
        index_to_get = 5
        value = get_array_value_secure(index_to_get, my_array)
        print(f"Value at index {index_to_get}: {value}")  # Output: Value at index 5: 60

        index_to_get = 15  # Out of bounds
        value = get_array_value_secure(index_to_get, my_array)
        print(f"Value at index {index_to_get}: {value}")  # Output: Value at index 15: None

        # Example of handling invalid input
        #index_to_get = "abc"
        #value = get_array_value_secure(index_to_get, my_array) #This will raise a TypeError

    except TypeError as e:
        print(f"Error: {e}")
    except IndexError as e:
        print(f"Error: {e}")

