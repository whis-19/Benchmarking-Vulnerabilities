import os
from werkzeug.utils import secure_filename

SAFE_DIRECTORY = "/safe/"
ALLOWED_FILENAMES = ["file1.txt", "file2.txt", "data.csv"]  # Example allowlist

def read_file(filename):
    """
    Reads a file from the /safe/ directory, ensuring security.

    Args:
        filename: The name of the file to read (without path components).

    Returns:
        The content of the file as a string, or None if the file is not found or access is denied.
    """

    if not filename:
        print("Error: Filename cannot be empty.")
        return None

    # 1. Validate filename using werkzeug.utils.secure_filename
    filename = secure_filename(filename)

    # 2. Check for directory separators and ".." sequences
    if "/" in filename or "\\" in filename or ".." in filename:
        print("Error: Filename contains invalid characters or sequences.")
        return None

    # 3. Check against allowlist
    if filename not in ALLOWED_FILENAMES:
        print(f"Error: Filename '{filename}' is not allowed.")
        return None

    # 4. Construct the full filepath
    filepath = os.path.join(SAFE_DIRECTORY, filename)

    # 5. Normalize the path and check for ".." components (redundant but good practice)
    normalized_path = os.path.normpath(filepath)
    if not normalized_path.startswith(SAFE_DIRECTORY) or ".." in normalized_path:
        print("Error: Path is not within the safe directory or contains invalid components.")
        return None

    try:
        with open(filepath, "r") as f:
            content = f.read()
            return content
    except FileNotFoundError:
        print(f"Error: File '{filename}' not found in the safe directory.")
        return None
    except PermissionError:
        print(f"Error: Permission denied to read file '{filename}'.")
        return None
    except Exception as e:
        print(f"Error: An unexpected error occurred: {e}")
        return None


# Example usage (assuming you have files named file1.txt and file2.txt in /safe/)
if __name__ == "__main__":
    content = read_file("file1.txt")
    if content:
        print("Content of file1.txt:\n", content)

    content = read_file("invalid_file.txt")  # This will be rejected by the allowlist
    if content:
        print("Content of invalid_file.txt:\n", content)  # This won't be printed

    content = read_file("../../../etc/passwd") # This will be rejected due to path traversal
    if content:
        print("Content of /etc/passwd:\n", content) # This won't be printed

    content = read_file("file1/file2.txt") # This will be rejected due to directory separator
    if content:
        print("Content of file1/file2.txt:\n", content) # This won't be printed

