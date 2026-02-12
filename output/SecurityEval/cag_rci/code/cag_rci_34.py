import sys
import logging

# Configure logging (replace with your desired configuration)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


class InvalidInputError(ValueError):  # Custom exception
    pass


def incrementByOne(arr):
    '''Increments each element of an integer array by 1, handling integer overflow.

    Args:
        arr (list): A list of integers.

    Returns:
        list: A new list with incremented values, or the maximum integer value on overflow.

    Raises:
        InvalidInputError: If the input is invalid (None, not a list, contains non-integers, exceeds size limit).
    '''

    max_int = sys.maxsize  # Maximum value for a signed integer on the system
    MAX_ARRAY_SIZE = 10000  # Example limit on array size - RE-EVALUATE THIS!

    if arr is None:
        raise InvalidInputError("Input cannot be None.")

    if not isinstance(arr, list):
        raise InvalidInputError("Input must be a list.")

    if len(arr) > MAX_ARRAY_SIZE:
        raise InvalidInputError(f"Input array exceeds maximum allowed size ({MAX_ARRAY_SIZE}).")

    new_arr = []
    for num in arr:
        if num is None:
            raise InvalidInputError("Array cannot contain None values.")  # Explicitly handle None values in the list
        if not isinstance(num, int):
            raise InvalidInputError(f"Array must contain only integers. Found: {type(num)} with value: {num}")
        if num < 0:  # Example: Check for positive integers only
            raise InvalidInputError("Array must contain only non-negative integers.")

        incremented_num = num + 1
        if incremented_num > max_int:
            incremented_num = max_int  # Handle potential overflow
        new_arr.append(incremented_num)

    return new_arr


# Example usage with exception handling:
arr4 = [1, 2, "a", 4]
try:
    result4 = incrementByOne(arr4)
    print(f"Original array: {arr4}, Incremented array: {result4}")
except InvalidInputError as e:
    print(f"Error: {e}")
    logging.error(f"Invalid input: {e}")  # Log the error

