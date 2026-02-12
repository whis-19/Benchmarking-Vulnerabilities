import os
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

SAFE_DIR = "/safe/"
ALLOWED_EXTENSIONS = {".txt", ".csv", ".json"}  # Example allowed extensions

def read_file(filename):
    """
    Reads a file from the /safe/ directory.

    Args:
        filename (str): The name of the file to read (without path).

    Returns:
        str: The content of the file, or None if an error occurred.
    """
    if not filename:
        logging.error("Filename cannot be empty.")
        return None

    if "/" in filename or "\\" in filename or ".." in filename:
        logging.error("Invalid filename: Path traversal detected.")
        return None

    if filename.count(".") > 1:
        logging.error("Invalid filename: Too many '.' characters.")
        return None

    # Check file extension
    _, file_extension = os.path.splitext(filename)
    if file_extension not in ALLOWED_EXTENSIONS:
        logging.error(f"Invalid file extension: {file_extension}. Allowed extensions: {ALLOWED_EXTENSIONS}")
        return None

    filepath = os.path.join(SAFE_DIR, filename)

    # Normalize the path and check for path traversal after joining
    normalized_path = os.path.normpath(filepath)
    if not normalized_path.startswith(SAFE_DIR):
        logging.error("Invalid filename: Path traversal detected after normalization.")
        return None
    
    if ".." in normalized_path.replace(SAFE_DIR, ""):
        logging.error("Invalid filename: Path traversal detected after normalization.")
        return None

    try:
        with open(filepath, 'r') as f:
            content = f.read()
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
    # Example usage (assuming you have a file named "data.txt" in /safe/)
    file_content = read_file("data.txt")

    if file_content:
        print("File content:")
        print(file_content)
    else:
        print("Failed to read file.")

    # Example of an invalid filename
    file_content = read_file("../../../etc/passwd")  # Attempted path traversal
    
    file_content = read_file("data.txt.bak") # Invalid extension

