import os
import logging

# Configure logging (optional, but recommended for security auditing)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

ALLOWED_EXTENSIONS = {'txt', 'pdf', 'csv'}  # Define allowed file extensions
SAFE_DIRECTORY = '/safe/'  # Define the safe directory

def is_safe_path(filename):
    """
    Validates the filename against security guidelines.

    Args:
        filename (str): The filename to validate.

    Returns:
        bool: True if the filename is safe, False otherwise.
    """

    if not filename:
        logging.warning("Filename is empty.")
        return False

    if "/" in filename or "\\" in filename:
        logging.warning("Filename contains directory separators.")
        return False

    if ".." in filename:
        logging.warning("Filename contains path traversal sequences.")
        return False

    if filename.count(".") > 1:
        logging.warning("Filename contains more than one dot.")
        return False

    extension = filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''
    if extension not in ALLOWED_EXTENSIONS:
        logging.warning(f"Filename has an invalid extension: {extension}")
        return False

    return True


def read_safe_file(filename):
    """
    Reads a file from the /safe/ directory after validating the filename.

    Args:
        filename (str): The name of the file to read.

    Returns:
        str: The content of the file, or None if an error occurred.
    """

    if not is_safe_path(filename):
        logging.error(f"Unsafe filename provided: {filename}")
        return None

    filepath = os.path.join(SAFE_DIRECTORY, filename)

    # Normalize the path to further prevent traversal attacks
    normalized_path = os.path.normpath(filepath)

    if not normalized_path.startswith(SAFE_DIRECTORY):
        logging.error(f"Path traversal detected: {normalized_path}")
        return None

    if ".." in normalized_path:
        logging.error(f"Path traversal detected in normalized path: {normalized_path}")
        return None

    try:
        with open(filepath, 'r') as f:
            content = f.read()
            logging.info(f"Successfully read file: {filepath}")
            return content
    except FileNotFoundError:
        logging.error(f"File not found: {filepath}")
        return None
    except IOError as e:
        logging.error(f"Error reading file: {filepath} - {e}")
        return None
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        return None


if __name__ == '__main__':
    # Example usage (replace with your actual input)
    file_to_read = 'my_document.txt'  # Example of a valid filename
    #file_to_read = '../etc/passwd' # Example of an invalid filename
    #file_to_read = 'my_document.txt.evil' # Example of an invalid filename
    #file_to_read = 'my/document.txt' # Example of an invalid filename
    #file_to_read = 'my_document..txt' # Example of an invalid filename

    # Create a dummy file for testing
    os.makedirs(SAFE_DIRECTORY, exist_ok=True)
    dummy_file_path = os.path.join(SAFE_DIRECTORY, 'my_document.txt')
    with open(dummy_file_path, 'w') as f:
        f.write("This is a test document.")

    content = read_safe_file(file_to_read)

    if content:
        print("File content:")
        print(content)
    else:
        print("Failed to read the file.")

    # Clean up the dummy file
    os.remove(dummy_file_path)
    os.rmdir(SAFE_DIRECTORY)

