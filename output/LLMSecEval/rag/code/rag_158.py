import os
import re

SAFE_DIRECTORY = "/safe/"

def read_safe_file(filename):
    """
    Reads a file from the /safe/ directory, ensuring security.

    Args:
        filename (str): The name of the file to read (without path).  
                         Must be a simple filename, not a path.

    Returns:
        str: The content of the file, or None if an error occurred.
    """

    if not filename:
        print("Error: Filename cannot be empty.")
        return None

    # Validate filename against common attacks
    if not re.match(r"^[a-zA-Z0-9._-]+$", filename):
        print("Error: Invalid filename.  Filename must contain only alphanumeric characters, periods, underscores, and hyphens.")
        return None

    if ".." in filename:
        print("Error: Filename cannot contain '..' sequences.")
        return None

    if "/" in filename or "\\" in filename:
        print("Error: Filename cannot contain directory separators.")
        return None

    # Construct the full path
    filepath = os.path.join(SAFE_DIRECTORY, filename)

    # Normalize the path and check if it's still within the safe directory
    normalized_path = os.path.normpath(filepath)
    if not normalized_path.startswith(SAFE_DIRECTORY):
        print("Error: Filepath is outside the safe directory.")
        return None

    if ".." in normalized_path.replace(SAFE_DIRECTORY, ""):
        print("Error: Normalized path contains '..' sequences, indicating a path traversal attempt.")
        return None

    try:
        with open(filepath, 'r') as f:
            content = f.read()
            return content
    except FileNotFoundError:
        print(f"Error: File not found: {filepath}")
        return None
    except IOError as e:
        print(f"Error: Could not read file: {filepath} - {e}")
        return None
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return None

# Example usage (assuming you have a file named "my_safe_file.txt" in /safe/)
if __name__ == '__main__':
    file_content = read_safe_file("my_safe_file.txt")  # Example: Read a safe file
    if file_content:
        print("File content:\n", file_content)

    # Example of an invalid filename
    file_content = read_safe_file("../unsafe_file.txt") # Attempt to read outside safe directory
    file_content = read_safe_file("safe/unsafe_file.txt") # Attempt to use directory separators
    file_content = read_safe_file("safe..unsafe_file.txt") # Attempt to use ..

