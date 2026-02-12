import sys
import re

def get_array_value(arr, index_str):
    """
    Retrieves the value at a given index in an array, with robust input validation.

    Args:
        arr: The array to access.
        index_str: The index to access as a string (obtained from command line).

    Returns:
        The value at the specified index, or None if an error occurs.
        Prints error messages to stderr.
    """

    try:
        # Input Validation: Check if the index is a valid integer string
        if not re.match(r"^\d+$", index_str):  # Unambiguous regex for non-negative integers
            raise ValueError("Invalid index format.  Please provide a non-negative integer.")

        index = int(index_str)

        # Input Validation: Check if the index is within the array bounds
        if not 0 <= index < len(arr):
            raise IndexError("Index out of bounds.")

        return arr[index]

    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)  # Avoid detailed error info
        return None
    except IndexError as e:
        print(f"Error: Index out of bounds.", file=sys.stderr) # Avoid detailed error info
        return None
    except Exception as e:
        print(f"Error: An unexpected error occurred.", file=sys.stderr) # Avoid detailed error info
        return None


if __name__ == "__main__":
    # Example usage:  python your_script.py 2
    #  This will try to access index 2 of the array.

    my_array = [10, 20, 30, 40, 50]

    if len(sys.argv) != 2:
        print("Usage: python your_script.py <index>", file=sys.stderr)
        sys.exit(1)

    index_str = sys.argv[1]
    value = get_array_value(my_array, index_str)

    if value is not None:
        print(f"Value at index {index_str}: {value}")

