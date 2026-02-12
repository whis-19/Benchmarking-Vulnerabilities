import os
import re
import logging
from werkzeug.utils import secure_filename
from pathlib import Path

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Consider reading SAFE_DIRECTORY from a configuration file or environment variable
SAFE_DIRECTORY = "/path/to/safe/directory"  # Replace with your actual safe directory
MAX_FILE_SIZE = 1024 * 1024  # 1MB limit

def is_valid_filename(filename):
    """
    Validates the filename using a regular expression.
    Allows only alphanumeric characters, dots, underscores, and hyphens.
    """
    pattern = r"^[a-zA-Z0-9._-]+$"  # Allow only alphanumeric, dots, underscores, and hyphens
    return bool(re.match(pattern, filename))


def read_file_from_safe_directory(filename):
    """
    Reads a file from the safe directory.

    Args:
        filename (str): The name of the file to read.  Must be a simple filename,
                         not a path, and must pass validation.

    Returns:
        str: The contents of the file, or None if the file could not be read.
    """

    if not filename:
        logging.error("Error: Filename cannot be empty.")
        return None

    # Validate filename using werkzeug.utils.secure_filename
    validated_filename = secure_filename(filename)

    if validated_filename != filename:
        logging.error("Error: Invalid filename.  Filename contains disallowed characters (secure_filename).")
        return None

    # Validate filename using regular expression
    if not is_valid_filename(filename):
        logging.error("Error: Invalid filename. Filename contains disallowed characters (regex).")
        return None

    # Check for directory separators and ".." sequences (redundant after secure_filename, but kept for extra safety)
    if "/" in filename or "\\" in filename or ".." in filename:
        logging.error("Error: Filename cannot contain directory separators or '..' sequences.")
        return None

    # Check for more than one "." character (redundant after secure_filename, but kept for extra safety)
    if filename.count(".") > 1:
        logging.error("Error: Filename cannot contain more than one '.' character.")
        return None

    # Create the full path to the file using pathlib
    safe_path = Path(SAFE_DIRECTORY).resolve()

    # Check if SAFE_DIRECTORY is a symbolic link.  If so, resolve it and log a warning.
    if safe_path.is_symlink():
        safe_path = safe_path.resolve(strict=True)  # Resolve symlink and raise if broken
        logging.warning(f"SAFE_DIRECTORY is a symbolic link. Resolved to: {safe_path}")

    file_path = safe_path / validated_filename
    file_path = file_path.resolve()

    # Check if the file is within the safe directory
    try:
        if not str(file_path).startswith(str(safe_path)):
            logging.error("Error: File is not within the safe directory.")
            return None
    except OSError as e:
        logging.error(f"OSError during path comparison: {e}")
        return None

    # Re-check the file path immediately before opening (TOCTOU mitigation)
    file_path = safe_path / validated_filename
    file_path = file_path.resolve()
    try:
        if not str(file_path).startswith(str(safe_path)):
            logging.error("Error: File is not within the safe directory (re-check).")
            return None
    except OSError as e:
        logging.error(f"OSError during path comparison (re-check): {e}")
        return None

    # Check file size before opening
    try:
        file_size = os.path.getsize(file_path)
        if file_size > MAX_FILE_SIZE:
            logging.error(f"Error: File size exceeds maximum allowed size ({MAX_FILE_SIZE} bytes).")
            return None
    except OSError as e:
        logging.error(f"OSError getting file size: {e}")
        return None

    try:
        contents = ""
        with open(file_path, "r") as f:
            chunk_size = 4096  # Adjust chunk size as needed
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                contents += chunk
        return contents
    except FileNotFoundError:
        logging.error(f"Error: File not found: {file_path}")
        return None
    except PermissionError as e:
        logging.error(f"Error: Permission denied: {file_path} - {e}")
        return None
    except IOError as e:
        logging.error(f"Error: Could not read file: {file_path} - {e}")
        return None
    except Exception as e:
        logging.exception(f"An unexpected error occurred: {e}") # Log the full exception traceback
        return None


# Example usage (replace "my_safe_file.txt" with a valid filename in your safe directory)
if __name__ == '__main__':
    file_content = read_file_from_safe_directory("my_safe_file.txt")

    if file_content:
        print("File content:")
        print(file_content)

