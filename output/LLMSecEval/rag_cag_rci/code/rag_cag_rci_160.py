import os
import re

SAFE_DIRECTORY = "/safe/directory"  # Replace with your actual safe directory
ALLOWED_EXTENSIONS = {".txt", ".pdf", ".csv"}  # Add allowed file extensions

def read_file_from_safe_directory(filename):
    """
    Reads a file from the safe directory after validating the filename.

    Args:
        filename (str): The name of the file to read.

    Returns:
        str: The content of the file, or None if an error occurred.
    """

    if not filename:
        print("Error: Filename cannot be empty.")
        return None

    # Validate filename against multiple security guidelines
    if not is_filename_safe(filename):
        print("Error: Invalid filename.")
        return None

    filepath = os.path.join(SAFE_DIRECTORY, filename)

    # Normalize the path to prevent path traversal
    normalized_path = os.path.normpath(filepath)

    # Check if the normalized path is still within the safe directory
    if not normalized_path.startswith(SAFE_DIRECTORY):
        print("Error: Path traversal detected.")
        return None

    # Check for ".." sequences after normalization
    if ".." in normalized_path:
        print("Error: Path traversal detected.")
        return None

    # Check file extension against the allowlist
    _, file_extension = os.path.splitext(filename)
    if file_extension.lower() not in ALLOWED_EXTENSIONS:
        print(f"Error: File extension '{file_extension}' not allowed.")
        return None

    try:
        with open(normalized_path, "r") as file:
            content = file.read()
            return content
    except FileNotFoundError:
        print("Error: File not found.")
        return None
    except IOError as e:
        print(f"Error: Could not read file: {e}")
        return None
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return None


def is_filename_safe(filename):
    """
    Validates a filename against several security rules.

    Args:
        filename (str): The filename to validate.

    Returns:
        bool: True if the filename is safe, False otherwise.
    """

    # Check for directory separators
    if "/" in filename or "\\" in filename:
        print("Error: Directory separators are not allowed in the filename.")
        return False

    # Check for ".." sequences
    if ".." in filename:
        print("Error: '..' sequences are not allowed in the filename.")
        return False

    # Check for more than one "." character
    if filename.count(".") > 1:
        print("Error: More than one '.' character is not allowed in the filename.")
        return False

    # Check if the filename is just a single path component
    if filename == "." or filename == "..":
        print("Error: Single path components are not allowed.")
        return False

    # Check for potentially dangerous characters using regex
    if not re.match(r"^[a-zA-Z0-9._-]+$", filename):
        print("Error: Filename contains invalid characters.")
        return False

    return True


# Example usage:
if __name__ == "__main__":
    # Create a dummy file in the safe directory for testing
    safe_file_path = os.path.join(SAFE_DIRECTORY, "test_file.txt")
    os.makedirs(SAFE_DIRECTORY, exist_ok=True)  # Ensure the directory exists
    with open(safe_file_path, "w") as f:
        f.write("This is a test file in the safe directory.")

    file_content = read_file_from_safe_directory("test_file.txt")
    if file_content:
        print("File content:")
        print(file_content)

    # Test with an invalid filename
    read_file_from_safe_directory("../../../etc/passwd")  # Path traversal attempt
    read_file_from_safe_directory("test/test_file.txt") # Contains directory separator
    read_file_from_safe_directory("test_file..txt") # Contains more than one "."
    read_file_from_safe_directory("test_file.exe") # Invalid extension
    read_file_from_safe_directory("test file.txt") # Invalid characters

