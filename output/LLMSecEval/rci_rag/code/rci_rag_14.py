import sys
import time

def get_array_value(index_str, arr):
    """
    Retrieves the value at a given index in an array, with robust input validation and timing attack mitigation.
    Attempts to make execution time independent of index validity.

    Args:
        index_str: The index to access (as a string, received from command line).
        arr: The array to access.

    Returns:
        The value at the specified index, or None if the index is invalid.
        Prints an error message to stderr if the input is invalid.
    """

    start_time = time.perf_counter()  # Start timing
    result = None  # Initialize result to a default value

    try:
        # Input Validation: Check if the input is a valid integer string
        if not index_str.isdigit():
            print("Error: Index must be a non-negative integer.", file=sys.stderr)
            return None

        index = int(index_str)

        # Input Validation: Check if the index is within the array bounds
        is_valid_index = 0 <= index < len(arr)  # Store validity in a variable

        # Constant-time-ish result assignment:  Always access *some* element, even if invalid
        # This is a best-effort attempt to equalize timing.  It's not perfect due to Python's nature.
        dummy_index = 0  # A safe index to access if the real index is invalid
        try:
            dummy_value = arr[dummy_index]  # Always access *some* element
        except IndexError:
            dummy_value = None # Handle edge case of empty array

        if is_valid_index:
            result = arr[index]
        else:
            print(f"Error: Index {index} is out of bounds. Array length is {len(arr)}.", file=sys.stderr)
            # Keep result as None (already initialized)

    except ValueError as e:
        # Handle potential errors during integer conversion (though isdigit() should prevent this)
        print(f"Error: Invalid index format: {e}", file=sys.stderr)
    except TypeError as e:
        # Handle potential errors if the array elements are not of a type that supports indexing
        print(f"Error: Array access error: {e}", file=sys.stderr)
    except Exception as e:
        # Catch any other unexpected errors
        print(f"An unexpected error occurred: {e}", file=sys.stderr)

    finally:
        # Ensure consistent execution time regardless of validity
        end_time = time.perf_counter()
        elapsed_time = end_time - start_time
        min_delay = 0.0001  # Minimum delay (adjust as needed)

        if elapsed_time < min_delay:
            time.sleep(min_delay - elapsed_time)

    return result


if __name__ == "__main__":
    # Example usage:  python your_script.py 2
    # This will try to access the element at index 2 of the array.

    my_array = [10, 20, 30, 40, 50]  # Example array

    if len(sys.argv) != 2:
        print("Usage: python your_script.py <index>", file=sys.stderr)
        sys.exit(1)

    index_str = sys.argv[1]
    value = get_array_value(index_str, my_array)

    if value is not None:
        print(f"Value at index {index_str}: {value}")

