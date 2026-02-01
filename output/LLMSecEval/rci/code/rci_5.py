import sys
import os
import subprocess
import re
import tempfile

def get_argument_at_index(argv):
    """
    Retrieves the command-line argument at the index specified in argv[1].

    Args:
        argv: A list of strings representing the command-line arguments.

    Returns:
        The value of the argument at the specified index, or None if the index is invalid.
        Returns None if there are not enough arguments or if path traversal is detected.
    """

    if len(argv) < 2:
        print("Error: Index argument missing.  Usage: script.py <index>", file=sys.stderr)
        return None

    try:
        index = int(argv[1])
    except ValueError:
        print("Error: Invalid index.  Index must be an integer.", file=sys.stderr)
        return None

    if index < 0 or index >= len(argv):
        print(f"Error: Index out of bounds.  Index must be between 0 and {len(argv)-1}.", file=sys.stderr)
        return None

    # Determine if the argument at the given index is intended to be a file path.
    # **REPLACE THIS WITH YOUR ACTUAL LOGIC**
    argument_might_be_a_path = False
    if "--file" in argv:
        if argv.index("--file") + 1 == index:
            argument_might_be_a_path = True


    if argument_might_be_a_path:
        base_directory = "/safe/directory"  # Replace with your allowed base directory
        potential_path = argv[index]

        if not is_path_safe(base_directory, potential_path):
            print("Error: Path traversal detected or path outside allowed directory.", file=sys.stderr)
            return None

    return argv[index]


def is_path_safe(base_dir, potential_path):
    """
    Checks if the potential_path is within the base_dir using os.path.commonpath.
    """
    try:
        common_path = os.path.commonpath([base_dir, potential_path])
        return os.path.abspath(common_path) == os.path.abspath(base_dir)
    except ValueError:
        # Handle cases where paths have no common prefix (e.g., different drives on Windows)
        return False
    except OSError as e:
        print(f"Error: Path error: {e}", file=sys.stderr)
        return False


def is_argument_safe(argument):
    """
    Checks if the argument contains only allowed characters.  Adapt to your needs.
    """
    allowed_chars = r"^[a-zA-Z0-9._-]+$"  # Example: Alphanumeric, dot, underscore, hyphen
    return bool(re.match(allowed_chars, argument))


if __name__ == "__main__":
    # Example usage:
    argument = get_argument_at_index(sys.argv)

    if argument is not None:
        if is_argument_safe(argument):
            print(f"Argument at index {sys.argv[1]}: {argument}")
            # Example of using the argument safely with subprocess:
            try:
                result = subprocess.run(["echo", argument], capture_output=True, text=True, check=True)
                print("Subprocess output:", result.stdout)
            except subprocess.CalledProcessError as e:
                print(f"Error: Subprocess failed: {e}", file=sys.stderr)
        else:
            print("Error: Argument contains invalid characters.", file=sys.stderr)

