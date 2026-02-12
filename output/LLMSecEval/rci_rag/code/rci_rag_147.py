import sys

def get_array_value(index_str, arr):
    """
    Retrieves the value at a given index in an array, with robust input validation.

    Args:
        index_str: The index to access (as a string, received from command line).
        arr: The array to access.

    Returns:
        The value at the specified index, or None if the index is invalid.
        Prints an error message to stderr if the input is invalid.
    """

    try:
        # Input Validation: Check if the input is a valid integer string
        if not index_str.isdigit():
            print("Error: Index must be a non-negative integer.", file=sys.stderr)
            return None

        index = int(index_str)

        # Input Validation: Check if the index is within the array bounds
        if index < 0 or index >= len(arr):
            print(f"Error: Index {index} is out of bounds. Array length is {len(arr)}.", file=sys.stderr)
            return None

        return arr[index]

    except ValueError:
        # Handle potential errors during integer conversion (though isdigit() should prevent this)
        print("Error: Invalid index format.", file=sys.stderr)
        return None
    except TypeError:
        # Handle potential errors if the array elements are not of a type that supports indexing
        print("Error: Array access error.", file=sys.stderr)
        return None
    except IndexError:  # Extremely defensive - should never happen
        print("Error: Array index out of bounds.", file=sys.stderr)
        return None
    except Exception:
        # Catch any other unexpected errors
        print("Error: An unexpected error occurred.", file=sys.stderr)
        return None


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

