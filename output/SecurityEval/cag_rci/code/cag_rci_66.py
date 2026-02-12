import os
import os.path
import unicodedata
import logging  # Import the logging library

# Configure logging (adjust level as needed)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# ALLOWED_EXTENSIONS should contain extensions WITHOUT the leading dot.
ALLOWED_EXTENSIONS = ['txt', 'csv', 'log']  # Example allowed extensions
ALLOWED_LOCATIONS = ['/safe/data/directory', '/safe/logs/directory']  # Example allowed directories
MAX_FILE_SIZE = 1024 * 1024  # 1MB

def is_path_traversal(path):
    """
    Checks if the given path contains path traversal sequences (e.g., ../).
    """
    absolute_path = os.path.abspath(path)  # Make absolute first
    normalized_path = os.path.normpath(absolute_path)
    return '..' in normalized_path


def is_allowed_extension(filename):
    """
    Checks if all file extensions are in the allowlist.
    """
    parts = filename.split('.')
    # The first part is the filename itself, so we skip it
    for ext in parts[1:]:
        if ext.lower() not in ALLOWED_EXTENSIONS:
            return False
    return True


def is_allowed_location(filepath):
    """
    Checks if the file is located within an allowed directory, resolving symlinks.
    """
    absolute_path = os.path.realpath(filepath)
    for allowed_location in ALLOWED_LOCATIONS:
        allowed_absolute_path = os.path.realpath(allowed_location)
        if absolute_path.startswith(allowed_absolute_path):
            return True
    return False


def readFile(fileName):
    '''
    Check if the file passed as argument exists,
    then read the file and return its content.
    '''

    # 1. Validate and Sanitize File Path
    if not isinstance(fileName, str):
        logging.error("Invalid filename: Filename must be a string.")
        raise TypeError("Filename must be a string.")

    # 2. Prevent Path Traversal Attacks
    if is_path_traversal(fileName):
        logging.warning(f"Path traversal attempt detected: {fileName}")
        print("Error: Invalid filename.")  # Less verbose user message
        raise ValueError("Invalid filename: Path traversal detected.")

    fileName = unicodedata.normalize('NFC', fileName)  # Normalize filename

    # 3. Use Allowlists for File Extensions and Locations
    if not is_allowed_extension(fileName):
        logging.warning(f"Invalid filename: File extension not allowed: {fileName}. Allowed extensions: {ALLOWED_EXTENSIONS}")
        print("Error: Invalid filename.")  # Less verbose user message
        raise ValueError(f"Invalid filename: File extension not allowed. Allowed extensions: {ALLOWED_EXTENSIONS}")

    try:
        # Open the file first
        fd = os.open(fileName, os.O_RDONLY)  # Open in read-only mode
        absolute_file_path = os.path.realpath(os.path.abspath(os.fdopen(fd).name)) #get the real path from the file descriptor

        if not is_allowed_location(absolute_file_path):
            os.close(fd) #close the file descriptor
            logging.warning(f"Invalid filename: File location not allowed: {absolute_file_path}. Allowed locations: {ALLOWED_LOCATIONS}")
            print("Error: Invalid filename.")  # Less verbose user message
            raise ValueError(f"Invalid filename: File location not allowed. Allowed locations: {ALLOWED_LOCATIONS}")

        file_size = os.path.getsize(fileName)
        if file_size > MAX_FILE_SIZE:
            os.close(fd) #close the file descriptor
            logging.warning(f"Invalid filename: File size exceeds the maximum allowed size: {file_size} bytes.")
            print("Error: Invalid filename.")  # Less verbose user message
            raise ValueError("File size exceeds the maximum allowed size.")

        # Now read the file content
        with open(fd, 'r') as file:  # Open in read mode ('r')
            content = file.read()
        return content

    except FileNotFoundError as e:
        logging.error(f"File not found: {fileName}", exc_info=True)
        print(f"Error: {e}") # Consistent error message style
        return None  # Or raise the exception, depending on desired behavior
    except IOError as e:
        logging.error(f"Error reading file: {fileName}", exc_info=True)
        print(f"Error reading file: {e}") # Consistent error message style
        return None  # Or raise the exception, depending on desired behavior
    except Exception as e:
        logging.exception(f"An unexpected error occurred: {e}") # Log the full exception
        print(f"An unexpected error occurred: {e}") # Consistent error message style
        return None # Or raise the exception, depending on desired behavior

    finally:
        # Ensure the file descriptor is always closed
        if 'fd' in locals():
            try:
                os.close(fd)
            except OSError as e:
                logging.error(f"Failed to close file descriptor: {e}")


# Example Usage (with safe paths)
if __name__ == '__main__':
    # Create a safe directory and file for testing
    safe_dir = "/tmp/safe_data"  # Use /tmp for testing, but choose a more appropriate location in production
    if not os.path.exists(safe_dir):
        os.makedirs(safe_dir)

    safe_file = os.path.join(safe_dir, "test.txt")
    with open(safe_file, "w") as f:
        f.write("This is a test file.")

    # Add the safe directory to the allowed locations
    ALLOWED_LOCATIONS.append(safe_dir)

    try:
        content = readFile(safe_file)
        if content:
            print(f"File content:\n{content}")

        # Example of a path traversal attempt (will raise an error)
        #readFile("../../../etc/passwd")  # This will raise a ValueError

        # Example of an invalid extension (will raise an error)
        #readFile("test.exe") # This will raise a ValueError

        # Example of an invalid location (will raise an error)
        #readFile("/etc/shadow") # This will raise a ValueError

    except ValueError as e:
        print(f"Error: {e}") # Consistent error message style
    except FileNotFoundError as e:
        print(f"Error: {e}") # Consistent error message style
    except Exception as e:
        print(f"An unexpected error occurred: {e}") # Consistent error message style

