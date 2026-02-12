import os
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

SAFE_DIRECTORY = "/app/safe_files"  # Define the safe directory
ALLOWED_EXTENSIONS = {".txt", ".pdf", ".csv"}  # Define allowed file extensions

def read_file_from_safe_directory(filename):
    """
    Reads a file from the safe directory after validating the filename.

    Args:
        filename (str): The name of the file to read.

    Returns:
        str: The content of the file, or None if an error occurred.
    """
    if not filename:
        logging.error("Filename cannot be empty.")
        return None

    if "/" in filename or "\\" in filename:
        logging.error("Filename cannot contain path separators.")
        return None

    if ".." in filename:
        logging.error("Filename cannot contain '..' for path traversal protection.")
        return None

    if filename.count(".") > 1:
        logging.error("Filename cannot contain more than one '.' character.")
        return None

    # Check file extension against allowlist
    file_extension = os.path.splitext(filename)[1]
    if file_extension not in ALLOWED_EXTENSIONS:
        logging.error(f"File extension '{file_extension}' is not allowed.")
        return None

    # Construct the full file path
    filepath = os.path.join(SAFE_DIRECTORY, filename)

    # Normalize the path and check if it's still within the safe directory
    normalized_path = os.path.normpath(filepath)
    if not normalized_path.startswith(SAFE_DIRECTORY):
        logging.error("Filepath is outside the safe directory.")
        return None

    try:
        with open(filepath, "r") as file:
            content = file.read()
            return content
    except FileNotFoundError:
        logging.error(f"File not found: {filename}")
        return None
    except IOError as e:
        logging.error(f"Error reading file: {e}")
        return None
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        return None

if __name__ == '__main__':
    # Example usage:
    file_content = read_file_from_safe_directory("my_document.txt")

    if file_content:
        print("File content:")
        print(file_content)
    else:
        print("Failed to read file.")

    # Example of an invalid filename:
    file_content = read_file_from_safe_directory("../../../etc/passwd") # Path traversal attempt
    if file_content:
        print("File content:")
        print(file_content)
    else:
        print("Failed to read file.")

    file_content = read_file_from_safe_directory("my_document.txt.exe") # Invalid extension
    if file_content:
        print("File content:")
        print(file_content)
    else:
        print("Failed to read file.")

