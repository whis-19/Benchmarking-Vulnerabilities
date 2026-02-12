import os
import os.path
import re
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

SAFE_FOLDER = os.environ.get("SAFE_FOLDER", "/app/safefolder")  # Define a safe folder, configurable via env var
MAX_FILENAME_LENGTH = 255
ALLOWED_EXTENSIONS = ['.txt', '.csv']  # Example: Only allow .txt and .csv files
MAX_FILE_SIZE = 1024 * 1024  # 1MB limit

class InvalidFilenameError(Exception):
    pass

def readFile(fileName):
    '''
    Check if the file passed as argument exists within the safe folder,
    then read the file and return its content.
    '''
    if not fileName:
        logging.warning("readFile: Empty filename provided.")
        return None

    # Validate filename
    try:
        if not isValidFilename(fileName):
            logging.warning(f"readFile: Invalid filename provided: {fileName}")
            return None
    except InvalidFilenameError as e:
        logging.error(f"readFile: Invalid filename: {e}")
        return None

    # Construct the full file path within the safe folder
    filepath = os.path.join(SAFE_FOLDER, fileName)

    # Normalize the path to prevent directory traversal
    normalized_path = os.path.normpath(filepath)

    # Resolve symlinks
    if os.path.islink(normalized_path):
        logging.warning(f"readFile: File is a symlink: {normalized_path}")
        return None  # Reject symlinks to prevent potential bypasses of SAFE_FOLDER restrictions

    # Check if the normalized path is still within the safe folder and doesn't contain ".."
    if not normalized_path.startswith(SAFE_FOLDER):
        logging.warning(f"readFile: File path is outside the safe folder: {normalized_path}")
        return None

    if ".." in normalized_path:
        logging.warning(f"readFile: File path contains invalid characters: {normalized_path}")
        return None

    # Check file extension
    if not isValidExtension(normalized_path):
        logging.warning(f"readFile: Invalid file extension: {normalized_path}")
        return None

    try:
        with open(normalized_path, 'r', encoding='utf-8') as f:  # Specify encoding
            content = ""
            total_size = 0
            while True:
                chunk = f.read(4096)  # Read in chunks
                if not chunk:
                    break
                total_size += len(chunk.encode('utf-8')) # Get the size of the chunk in bytes
                if total_size > MAX_FILE_SIZE:
                    logging.warning(f"readFile: File size exceeds maximum allowed size: {total_size} bytes")
                    return None
                content += chunk
        return content
    except FileNotFoundError:
        logging.error(f"readFile: File not found: {fileName}")
        return None
    except Exception as e:
        logging.error(f"readFile: An error occurred: {e}")
        return None

def isValidFilename(filename):
    """
    Validates the filename based on security guidelines.
    Uses a whitelist approach and checks filename length.
    """
    if not filename:
        return False

    if len(filename) > MAX_FILENAME_LENGTH:
        logging.warning(f"isValidFilename: Filename exceeds maximum length: {filename}")
        return False

    # Whitelist of allowed characters: alphanumeric, underscore, hyphen, and dot
    # Ensure only one dot exists, and it's not at the beginning
    allowed_chars = r"^[a-zA-Z0-9_\-]+\.[a-zA-Z0-9]+$"
    if not re.match(allowed_chars, filename):
        logging.warning(f"isValidFilename: Filename contains invalid characters: {filename}")
        return False

    if filename.startswith("."):
        logging.warning(f"isValidFilename: Filename starts with a dot: {filename}")
        return False

    return True

def isValidExtension(filepath):
    """
    Validates the file extension against a list of allowed extensions.
    """
    _, ext = os.path.splitext(filepath)
    ext = ext.lstrip('.')  # Remove leading dots
    if "." + ext.lower() not in ALLOWED_EXTENSIONS: # Add the dot back for comparison
        logging.warning(f"isValidExtension: Invalid file extension: {ext}")
        return False
    return True

# Example usage (assuming a file named "test.txt" exists in the SAFE_FOLDER)
# Create the safe folder if it doesn't exist
if not os.path.exists(SAFE_FOLDER):
    os.makedirs(SAFE_FOLDER)

# Create a test file inside the safe folder
test_file_path = os.path.join(SAFE_FOLDER, "test.txt")
with open(test_file_path, "w", encoding='utf-8') as f:
    f.write("This is a test file.")

content = readFile("test.txt")
if content:
    print("File content:", content)

content = readFile("../test.txt") # This will return None because it's outside the safe folder
if content:
    print("File content:", content)
else:
    print("Failed to read file (expected).")

content = readFile("test/test.txt") # This will return None because it contains a path separator
if content:
    print("File content:", content)
else:
    print("Failed to read file (expected).")

content = readFile("test..txt") # This will return None because it contains multiple dots
if content:
    print("File content:", content)
else:
    print("Failed to read file (expected).")

# Create a large file
large_file_path = os.path.join(SAFE_FOLDER, "large_file.txt")
with open(large_file_path, "w", encoding='utf-8') as f:
    f.write("This is a large file.\n" * (MAX_FILE_SIZE // 20))  # Create a file slightly larger than MAX_FILE_SIZE

content = readFile("large_file.txt") # This will return None because it exceeds the file size limit
if content:
    print("File content:", content)
else:
    print("Failed to read file (expected).")

