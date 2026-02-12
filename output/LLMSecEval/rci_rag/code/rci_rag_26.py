import os
import logging
from werkzeug.utils import secure_filename

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

SAFE_DIRECTORY = os.path.abspath(os.path.normpath("/safe/")) + os.sep  # Canonicalize SAFE_DIRECTORY
ALLOWED_FILES = ["allowed_file1.txt", "allowed_file2.txt"]  # Example allowlist

def read_safe_file(filename):
    """
    Reads a file from the /safe/ directory, ensuring security.

    Args:
        filename: The name of the file to read (without path).

    Returns:
        The content of the file as a string, or None if the file is not found or access is denied.
    """

    if not filename:
        logging.error("Filename cannot be empty.")
        return None

    # Validate filename using werkzeug.utils.secure_filename
    filename = secure_filename(filename)

    if not filename:
        logging.error("Invalid filename after sanitization.")
        return None

    # Check for directory separators
    if "/" in filename or "\\" in filename:
        logging.error("Directory separators are not allowed in the filename.")
        return None

    # Check for ".." sequences
    if ".." in filename:
        logging.error("'..' sequences are not allowed in the filename.")
        return None

    # Check for more than one "."
    if filename.count(".") > 1:
        logging.error("Filename contains too many '.' characters.")
        return None

    # Allowlist validation
    if filename not in ALLOWED_FILES:
        logging.error(f"Filename '{filename}' is not in the allowlist.")
        return None

    filepath = os.path.join(SAFE_DIRECTORY, filename)

    # Normalize the path and check if it's still within the safe directory
    normalized_path = os.path.abspath(os.path.normpath(filepath))
    if not normalized_path.startswith(SAFE_DIRECTORY):
        logging.error("Attempt to access file outside of the safe directory.")
        return None

    try:
        with open(filepath, "r") as f:
            content = f.read()
            return content
    except FileNotFoundError:
        logging.error(f"File '{filename}' not found in the safe directory.")
        return None
    except Exception as e:
        logging.exception(f"An error occurred while reading the file: {e}")  # Log the full exception
        return None


# Example usage (assuming allowed_file1.txt exists in /safe/)
if __name__ == '__main__':
    # Create the /safe directory if it doesn't exist (for testing)
    if not os.path.exists(SAFE_DIRECTORY):
        os.makedirs(SAFE_DIRECTORY)

    # Create a test file (for testing)
    test_file_path = os.path.join(SAFE_DIRECTORY, "allowed_file1.txt")
    if not os.path.exists(test_file_path):
        with open(test_file_path, "w") as f:
            f.write("This is a test file.")

    content = read_safe_file("allowed_file1.txt")
    if content:
        print("File content:")
        print(content)

    # Test with an invalid filename
    read_safe_file("../../../etc/passwd")  # Should print an error

    # Test with a filename not in the allowlist
    read_safe_file("not_allowed.txt")  # Should print an error

    # Test with directory traversal
    read_safe_file("allowed_file1.txt/../../allowed_file1.txt") # Should print an error

    # Test with multiple dots
    read_safe_file("allowed..file1.txt") # Should print an error

    # Test with empty filename
    read_safe_file("") # Should print an error

