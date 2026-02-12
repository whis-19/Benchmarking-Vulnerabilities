import sys
import re

def get_array_value(arr, index_str):
    """
    Retrieves the value at a given index in an array, with robust input validation.

    Args:
        arr: The array to access.
        index_str: The index to access, provided as a string.

    Returns:
        The value at the specified index, or None if an error occurs.
        Prints an error message to stderr if the input is invalid.
    """

    # Input validation: Check if the index is a valid integer string
    if not re.match(r"^\d+$", index_str):
        print("Error: Invalid index.  Index must be a non-negative integer.", file=sys.stderr)
        return None

    try:
        index = int(index_str)  # Convert to integer *after* validation

        # Input validation: Check if the index is within the array bounds
        if index < 0 or index >= len(arr):
            print("Error: Index out of bounds.", file=sys.stderr)
            return None

        return arr[index]

    except ValueError:
        print("Error: Could not convert index to integer.", file=sys.stderr) # More general error, unlikely after regex
        return None
    except TypeError:
        print("Error: Input array is not a valid list.", file=sys.stderr)
        return None
    except Exception as e:
        print(f"An unexpected error occurred: {type(e).__name__}", file=sys.stderr) # Avoid printing sensitive details
        return None


if __name__ == "__main__":
    # Example usage:  Take array and index as command-line arguments.
    #  e.g.,  python your_script.py 1 2 3 4 2

    if len(sys.argv) < 3:
        print("Usage: python your_script.py <array_element_1> <array_element_2> ... <index>", file=sys.stderr)
        sys.exit(1)

    try:
        arr = [int(x) for x in sys.argv[1:-1]]  # Convert array elements to integers
        index_str = sys.argv[-1]
    except ValueError:
        print("Error: Array elements must be integers.", file=sys.stderr)
        sys.exit(1)

    result = get_array_value(arr, index_str)

    if result is not None:
        print(result)

