import os
from werkzeug.utils import secure_filename

SAFE_DIRECTORY = "/safe/"
ALLOWED_FILENAMES = ["file1.txt", "file2.txt", "data.csv"]  # Example allowlist

def read_safe_file(filename):
    """
    Reads a file from the /safe/ directory, ensuring security.

    Args:
        filename: The name of the file to read (without path).

    Returns:
        The content of the file as a string, or None if the file is not found or access is denied.
    """

    if not filename:
        print("Error: Filename cannot be empty.")
        return None

    # 1. Validate filename using werkzeug.utils.secure_filename
    filename = secure_filename(filename)

    if not filename:
        print("Error: Invalid filename after sanitization.")
        return None

    # 2. Check for directory separators and ".." sequences
    if "/" in filename or "\\" in filename or ".." in filename:
        print("Error: Filename contains invalid characters or sequences.")
        return None

    # 3. Check against allowlist
    if filename not in ALLOWED_FILENAMES:
        print(f"Error: Filename '{filename}' is not in the allowlist.")
        return None

    # 4. Construct the full path
    filepath = os.path.join(SAFE_DIRECTORY, filename)

    # 5. Normalize the path and check if it's still within the safe directory
    normalized_path = os.path.normpath(filepath)
    if not normalized_path.startswith(SAFE_DIRECTORY):
        print("Error: Attempt to access file outside of safe directory.")
        return None

    # 6. Check if the normalized path contains ".."
    if ".." in normalized_path.replace(SAFE_DIRECTORY, ""):
        print("Error: Path contains '..' sequence after normalization.")
        return None

    try:
        with open(filepath, "r") as f:
            content = f.read()
            return content
    except FileNotFoundError:
        print(f"Error: File '{filename}' not found in '{SAFE_DIRECTORY}'.")
        return None
    except Exception as e:
        print(f"Error: An error occurred while reading the file: {e}")
        return None


# Example usage:
if __name__ == '__main__':
    file_content = read_safe_file("file1.txt")  # Valid filename from allowlist
    if file_content:
        print("File content:\n", file_content)

    file_content = read_safe_file("invalid_file.txt")  # Not in allowlist
    file_content = read_safe_file("../unsafe_file.txt") # Contains ".."
    file_content = read_safe_file("file1/file.txt") # Contains "/"
    file_content = read_safe_file("file1..txt") # Contains ".." after secure_filename

