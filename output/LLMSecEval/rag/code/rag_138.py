import sys
import os

def get_argument_at_index(argv):
    """
    Retrieves the value at the index specified in argv[1] from the argv array.

    Args:
        argv: A list of strings representing the command-line arguments.

    Returns:
        The value at the specified index in argv, or None if an error occurs.
    """

    if len(argv) < 2:
        print("Error: Index argument missing.  Please provide an index as the second argument.")
        return None

    try:
        index_str = argv[1]
        # Validate that the index is a non-negative integer
        if not index_str.isdigit():
            print("Error: Index must be a non-negative integer.")
            return None

        index = int(index_str)

        # Check for potential integer overflow before using the index.
        # This is crucial for security, especially if the index is used to access memory.
        if index > sys.maxsize:
            print("Error: Index is too large.")
            return None

        # Check if the index is within the bounds of the argv array.
        if index < 0 or index >= len(argv):
            print(f"Error: Index {index} is out of bounds. argv length is {len(argv)}.")
            return None

        return argv[index]

    except ValueError:
        print("Error: Invalid index format.  Please provide a valid integer index.")
        return None
    except Exception as e:
        print(f"An unexpected error occurred: {type(e).__name__}") # Avoid printing detailed error messages
        return None


if __name__ == "__main__":
    result = get_argument_at_index(sys.argv)
    if result is not None:
        print(result)

