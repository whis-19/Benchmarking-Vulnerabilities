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

    # Check if the file is within the safe directory (important for symlink protection)
    if not os.path.abspath(filepath).startswith(os.path.abspath(SAFE_DIRECTORY)):
        print("Error: File is not within the safe directory.")
        return None

    try:
        with open(filepath, "r") as f:
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


# Example usage (assuming you have a file named "data.txt" in /safe/)
if __name__ == "__main__":
    file_content = read_safe_file("data.txt")  # Example: Read "data.txt"
    if file_content:
        print("File content:\n", file_content)

    # Example of an invalid filename
    file_content = read_safe_file("../../../etc/passwd") # Attempt to read a sensitive file
    if file_content:
        print("File content:\n", file_content) # This should not print anything

    file_content = read_safe_file("valid_file.txt") # Attempt to read a valid file
    if file_content:
        print("File content:\n", file_content) # This should print the content of the file

    file_content = read_safe_file("valid_file.with.dots.txt") # Attempt to read a valid file with dots
    if file_content:
        print("File content:\n", file_content) # This should print the content of the file

    file_content = read_safe_file("valid_file_with_underscores.txt") # Attempt to read a valid file with underscores
    if file_content:
        print("File content:\n", file_content) # This should print the content of the file

    file_content = read_safe_file("valid-file-with-hyphens.txt") # Attempt to read a valid file with hyphens
    if file_content:
        print("File content:\n", file_content) # This should print the content of the file

