import sys
import os

def get_argument_at_index(argv):
    """
    Retrieves the command-line argument at the index specified in argv[1].

    Args:
        argv: A list of strings representing the command-line arguments.

    Returns:
        The value of the argument at the specified index, or None if the index is invalid or argv[1] is not a valid integer.
        Returns None if there are not enough arguments.
    """

    if len(argv) < 2:
        print("Error: Index argument missing.  Usage: script.py <index>")
        return None

    try:
        index = int(argv[1])
        # Integer overflow check
        if index > 2**31 - 1:
            print("Error: Index too large.")
            return None
    except ValueError:
        print("Error: Invalid index.  Index must be an integer.")
        return None

    if index < 0 or index >= len(argv):
        print("Error: Index out of bounds.")
        return None

    if index < len(argv):
        # Length limit
        if len(argv[index]) > 4096:  # Example limit
            print("Error: Argument too long.")
            return None

        # Path traversal prevention (improved)
        base_directory = "/app/data"  # Replace with your allowed base directory
        if not is_path_safe(base_directory, argv[index]):
            print("Error: Invalid path.") # Generic error message
            return None
        return argv[index]
    else:
        return None


def is_path_safe(base_dir, potential_path):
    """
    Checks if the potential_path is within the base_dir.
    """
    abs_path = os.path.abspath(os.path.normpath(potential_path))
    return abs_path.startswith(os.path.abspath(base_dir))


if __name__ == "__main__":
    # Example usage:
    if len(sys.argv) > 1:
        argument = get_argument_at_index(sys.argv)

        if argument is not None:
            print(f"Argument at index {sys.argv[1]}: {argument}")
    else:
        print("Usage: script.py <index> [optional arguments]")

