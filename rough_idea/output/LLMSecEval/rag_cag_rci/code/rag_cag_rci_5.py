import sys
import ast

def get_argument_at_index(argv):
    """
    Returns the value at the index provided in argv[1], after validation.

    Args:
        argv: A list of strings representing the command line arguments.

    Returns:
        The value at the specified index, or None if an error occurs.
    """

    if len(argv) < 2:
        print("Error: Index argument is missing.")
        return None

    try:
        index_str = argv[1]
        # Validate that the index is an integer.  Use a regex for safety.
        import re
        if not re.match(r"^-?\d+$", index_str):
            print("Error: Index must be an integer.")
            return None

        index = int(index_str)

        if len(argv) < 3:
            print("Error: Not enough arguments. Need at least one argument to access.")
            return None

        # Access the element at the validated index.  Start from argv[2]
        if index < 0:
            print("Error: Index must be non-negative.")
            return None

        if index + 2 >= len(argv):
            print("Error: Index out of bounds.")
            return None

        return argv[index + 2]  # Adjust index to account for argv[0] and argv[1]

    except ValueError:
        print("Error: Invalid index format.")
        return None
    except IndexError:
        print("Error: Index out of bounds.")
        return None
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return None


if __name__ == "__main__":
    # Example usage:
    # python your_script.py 1 arg1 arg2 arg3
    result = get_argument_at_index(sys.argv)
    if result:
        print(f"Value at index: {result}")

