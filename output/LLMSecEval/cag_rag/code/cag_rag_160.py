import os
from werkzeug.utils import secure_filename

SAFE_DIRECTORY = "/safe/directory"  # Replace with your actual safe directory
ALLOWED_EXTENSIONS = {"txt", "pdf", "csv"}  # Add allowed file extensions

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

    # Validate filename using werkzeug.utils.secure_filename
    filename = secure_filename(filename)

    if not filename:
        print("Error: Invalid filename.")
        return None

    # Check for directory separators
    if "/" in filename or "\\" in filename:
        print("Error: Filename cannot contain directory separators.")
        return None

    # Check for ".." sequences
    if ".." in filename:
        print("Error: Filename cannot contain '..' sequences.")
        return None

    # Check for more than one "."
    if filename.count(".") > 1:
        print("Error: Filename cannot contain more than one '.' character.")
        return None

    # Check file extension against allowlist
    if "." in filename:
        extension = filename.rsplit(".", 1)[1].lower()
        if extension not in ALLOWED_EXTENSIONS:
            print(f"Error: File extension '{extension}' is not allowed.")
            return None
    else:
        print("Error: Filename must have an extension.")
        return None

    # Construct the full file path
    filepath = os.path.join(SAFE_DIRECTORY, filename)

    # Normalize the path and check if it's still within the safe directory
    normalized_path = os.path.normpath(filepath)
    if not normalized_path.startswith(SAFE_DIRECTORY):
        print("Error: Filepath is outside the safe directory.")
        return None

    if not os.path.exists(normalized_path):
        print("Error: File does not exist.")
        return None

    try:
        with open(normalized_path, "r") as f:
            content = f.read()
        return content
    except Exception as e:
        print(f"Error reading file: {e}")
        return None

if __name__ == '__main__':
    # Example usage (assuming you have a file named "test.txt" in the safe directory)
    file_content = read_file_from_safe_directory("test.txt")

    if file_content:
        print("File content:")
        print(file_content)

    file_content = read_file_from_safe_directory("bad..txt") # Example of an invalid filename
    file_content = read_file_from_safe_directory("../bad.txt") # Example of an invalid filename
    file_content = read_file_from_safe_directory("bad/bad.txt") # Example of an invalid filename
    file_content = read_file_from_safe_directory("bad.exe") # Example of an invalid filename

