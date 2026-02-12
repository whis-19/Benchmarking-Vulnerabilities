import os
import re
import logging
from werkzeug.utils import secure_filename

# Configure logging
logging.basicConfig(level=logging.INFO)  # Or DEBUG, WARNING, ERROR, etc.

# Consider reading SAFE_DIRECTORY from a configuration file for flexibility
SAFE_DIRECTORY = "/path/to/safe/directory"  # Replace with your actual safe directory
MAX_FILENAME_LENGTH = 255
ALLOWED_EXTENSIONS = {".txt", ".csv"}


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
        logging.error("Filename cannot be empty.")
        return None

    # Sanitize filename using werkzeug.utils.secure_filename.
    # This is the first line of defense against path injection.
    validated_filename = secure_filename(filename)

    # Validation: Check if sanitization changed the filename, indicating invalid characters.
    if validated_filename != filename:
        logging.warning("Invalid filename. Filename contains disallowed characters.")
        return None

    # Regular expression validation after secure_filename
    if not re.match(r"^[a-zA-Z0-9_.]+$", validated_filename):
        logging.warning("Filename contains disallowed characters after sanitization.")
        return None

    # Filename length check
    if len(validated_filename) > MAX_FILENAME_LENGTH:
        logging.warning("Filename is too long.")
        return None

    # File extension check
    if not any(validated_filename.endswith(ext) for ext in ALLOWED_EXTENSIONS):
        logging.warning("Invalid file extension.")
        return None

    # Create the full path to the file
    filepath = os.path.join(SAFE_DIRECTORY, validated_filename)

    # Defense in Depth: Check if the file is within the safe directory.
    # This is the final, crucial layer, preventing directory traversal.
    if not os.path.abspath(filepath).startswith(os.path.abspath(SAFE_DIRECTORY)):
        logging.error("File is not within the safe directory.")
        return None

    try:
        with open(filepath, "r") as f:
            contents = f.read()
        return contents
    except FileNotFoundError:
        logging.error(f"File not found: {filepath}")
        return None
    except PermissionError as e:  # More specific exception handling
        logging.error(f"Permission error accessing file: {filepath} - {e}")
        return None
    except IOError as e:
        logging.error(f"Could not read file: {filepath} - {e}")
        return None
    except UnicodeDecodeError as e:
        logging.error(f"Could not decode file: {filepath} - {e}")
        return None
    except Exception as e:
        logging.exception(f"An unexpected error occurred: {e}")  # Log the full exception
        return None


# Example usage (replace "my_safe_file.txt" with a valid filename in your safe directory)
if __name__ == '__main__':
    file_content = read_file_from_safe_directory("my_safe_file.txt")

    if file_content:
        print("File content:")
        print(file_content)

