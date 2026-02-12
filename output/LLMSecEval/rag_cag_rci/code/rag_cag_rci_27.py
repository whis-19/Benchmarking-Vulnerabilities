import os
import re

SAFE_DIRECTORY = "/path/to/safe/directory"  # Replace with your actual safe directory
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

    # Validate filename against allowlist of known good patterns
    if not re.match(r"^[a-zA-Z0-9_-]+\.[a-zA-Z0-9]+$", filename):
        print("Error: Invalid filename format.  Only alphanumeric characters, underscores, hyphens, and a single extension are allowed.")
        return None

    if ".." in filename or "/" in filename or "\\" in filename:
        print("Error: Filename contains invalid characters or sequences (.., /, \\).")
        return None

    if filename.count(".") > 1:
        print("Error: Filename contains more than one '.' character.")
        return None

    file_extension = os.path.splitext(filename)[1]
    if file_extension not in ALLOWED_EXTENSIONS:
        print(f"Error: File extension '{file_extension}' is not allowed.")
        return None

    filepath = os.path.join(SAFE_DIRECTORY, filename)

    # Normalize the path and check for path traversal
    normalized_path = os.path.normpath(filepath)
    if not normalized_path.startswith(SAFE_DIRECTORY):
        print("Error: Path traversal detected.")
        return None

    if ".." in normalized_path.replace(SAFE_DIRECTORY, ""):
        print("Error: Path traversal detected after normalization.")
        return None

    try:
        with open(filepath, "r") as f:
            content = f.read()
            return content
    except FileNotFoundError:
        print(f"Error: File not found: {filename}")
        return None
    except IOError as e:
        print(f"Error: Could not read file: {e}")
        return None
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return None

if __name__ == '__main__':
    # Example usage (replace with user input)
    filename_to_read = "my_document.txt"  # Example valid filename
    # Create a dummy file for testing
    test_file_path = os.path.join(SAFE_DIRECTORY, filename_to_read)
    os.makedirs(SAFE_DIRECTORY, exist_ok=True)  # Ensure the directory exists
    with open(test_file_path, "w") as f:
        f.write("This is a test document.")

    file_content = read_file_from_safe_directory(filename_to_read)

    if file_content:
        print("File content:")
        print(file_content)

    # Example of an invalid filename
    invalid_filename = "../../../etc/passwd"
    read_file_from_safe_directory(invalid_filename)  # This will print an error message

    invalid_filename2 = "my_document.txt.exe"
    read_file_from_safe_directory(invalid_filename2) # This will print an error message

    invalid_filename3 = "my/document.txt"
    read_file_from_safe_directory(invalid_filename3) # This will print an error message

    invalid_filename4 = "my..document.txt"
    read_file_from_safe_directory(invalid_filename4) # This will print an error message

    invalid_filename5 = "my.document.more.txt"
    read_file_from_safe_directory(invalid_filename5) # This will print an error message

