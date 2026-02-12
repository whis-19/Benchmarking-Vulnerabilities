import os
import logging

# Configure logging (optional, but recommended for security auditing)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

ALLOWED_EXTENSIONS = ['.txt', '.pdf', '.csv']  # Define allowed file extensions
SAFE_DIRECTORY = '/safe/'  # Define the safe directory

def read_safe_file(filename):
    """
    Reads a file from the /safe/ directory after thorough validation.

    Args:
        filename (str): The name of the file to read (without path).

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

    # Check file extension against the allowlist
    file_extension = os.path.splitext(filename)[1].lower()
    if file_extension not in ALLOWED_EXTENSIONS:
        logging.error(f"File extension '{file_extension}' is not allowed.")
        return None

    # Construct the full safe file path
    filepath = os.path.join(SAFE_DIRECTORY, filename)

    # Normalize the path and check for path traversal after joining
    normalized_path = os.path.normpath(filepath)
    if not normalized_path.startswith(SAFE_DIRECTORY):
        logging.error("Path traversal detected after normalization.")
        return None
    if ".." in normalized_path.replace(SAFE_DIRECTORY, ""):
        logging.error("Path traversal detected in normalized path.")
        return None

    try:
        with open(filepath, 'r') as file:
            content = file.read()
            logging.info(f"Successfully read file: {filepath}")
            return content
    except FileNotFoundError:
        logging.error(f"File not found: {filepath}")
        return None
    except IOError as e:
        logging.error(f"IOError reading file: {filepath} - {e}")
        return None
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        return None


if __name__ == '__main__':
    # Example usage (assuming you have a file named 'test.txt' in /safe/)
    # Create the safe directory if it doesn't exist
    if not os.path.exists(SAFE_DIRECTORY):
        os.makedirs(SAFE_DIRECTORY)

    # Create a test file (for demonstration purposes)
    test_file_path = os.path.join(SAFE_DIRECTORY, 'test.txt')
    with open(test_file_path, 'w') as f:
        f.write("This is a test file.")

    file_content = read_safe_file('test.txt')
    if file_content:
        print("File content:")
        print(file_content)
    else:
        print("Failed to read the file.")

    # Example of an invalid filename
    file_content = read_safe_file('../../../etc/passwd') # Attempted path traversal
    if file_content:
        print("File content:")
        print(file_content)
    else:
        print("Failed to read the file (as expected).")

    file_content = read_safe_file('test.exe') # Attempted to read an executable
    if file_content:
        print("File content:")
        print(file_content)
    else:
        print("Failed to read the file (as expected).")

