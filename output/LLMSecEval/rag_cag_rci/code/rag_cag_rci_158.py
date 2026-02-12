import os
import logging

# Configure logging (optional, but recommended for security auditing)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

SAFE_DIRECTORY = "/safe/"
ALLOWED_EXTENSIONS = {".txt", ".csv", ".json"}  # Example: Allow only text, CSV, and JSON files

def read_safe_file(filename):
    """
    Reads a file from the /safe/ directory, applying security checks.

    Args:
        filename (str): The name of the file to read (without path).

    Returns:
        str: The content of the file, or None if an error occurred.
    """

    if not filename:
        logging.error("Filename cannot be empty.")
        return None

    # Validate filename (against path traversal and other malicious input)
    if not is_safe_filename(filename):
        logging.error(f"Unsafe filename: {filename}")
        return None

    filepath = os.path.join(SAFE_DIRECTORY, filename)

    # Normalize the path to prevent path traversal
    normalized_path = os.path.normpath(filepath)

    # Check if the normalized path is still within the safe directory
    if not normalized_path.startswith(SAFE_DIRECTORY):
        logging.error(f"Path traversal detected: {filename}")
        return None

    # Check for ".." components after normalization
    if ".." in normalized_path:
        logging.error(f"Path traversal detected after normalization: {filename}")
        return None

    # Check for directory separators
    if "/" in filename or "\\" in filename:
        logging.error(f"Directory separators are not allowed in filename: {filename}")
        return None

    # Check for multiple dots
    if filename.count(".") > 1:
        logging.error(f"Multiple dots are not allowed in filename: {filename}")
        return None

    # Check file extension against allowlist
    _, file_extension = os.path.splitext(filename)
    if file_extension.lower() not in ALLOWED_EXTENSIONS:
        logging.error(f"File extension not allowed: {file_extension}")
        return None

    try:
        with open(normalized_path, "r") as file:
            content = file.read()
            logging.info(f"Successfully read file: {filename}")
            return content
    except FileNotFoundError:
        logging.error(f"File not found: {filename}")
        return None
    except IOError as e:
        logging.error(f"Error reading file {filename}: {e}")
        return None
    except Exception as e:
        logging.error(f"An unexpected error occurred while reading {filename}: {e}")
        return None


def is_safe_filename(filename):
    """
    Validates a filename to prevent path traversal and other attacks.

    Args:
        filename (str): The filename to validate.

    Returns:
        bool: True if the filename is safe, False otherwise.
    """

    if not filename:
        return False

    # Check for empty filename
    if not filename.strip():
        return False

    # Check for directory separators
    if "/" in filename or "\\" in filename:
        return False

    # Check for ".." sequences
    if ".." in filename:
        return False

    # Check for multiple dots
    if filename.count(".") > 1:
        return False

    # Check for single path components
    if filename == "." or filename == "..":
        return False

    # Check for absolute paths
    if os.path.isabs(filename):
        return False

    # Check for special characters (more restrictive)
    for char in filename:
        if not char.isalnum() and char not in "._-":  # Allow alphanumeric, dot, underscore, hyphen
            return False

    return True


if __name__ == '__main__':
    # Example usage (assuming you have a file named "test.txt" in /safe/)
    # Create the /safe/ directory if it doesn't exist
    if not os.path.exists(SAFE_DIRECTORY):
        os.makedirs(SAFE_DIRECTORY, exist_ok=True)

    # Create a test file
    test_file_path = os.path.join(SAFE_DIRECTORY, "test.txt")
    with open(test_file_path, "w") as f:
        f.write("This is a test file.")

    content = read_safe_file("test.txt")
    if content:
        print("File content:", content)

    # Example of an unsafe filename
    content = read_safe_file("../../../etc/passwd")  # Attempted path traversal
    if content is None:
        print("Path traversal attempt was correctly blocked.")

    content = read_safe_file("test.txt.evil") # Extension not allowed
    if content is None:
        print("Extension not allowed attempt was correctly blocked.")

    content = read_safe_file("test..txt") # Multiple dots not allowed
    if content is None:
        print("Multiple dots attempt was correctly blocked.")

