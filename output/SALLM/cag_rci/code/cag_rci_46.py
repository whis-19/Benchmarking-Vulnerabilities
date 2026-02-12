import os
import logging
import unicodedata
import fcntl  # For file locking (Unix-like systems)
import resource # For resource limits
import magic # For file type detection

# Configure logging (optional, but recommended for security)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

ALLOWED_EXTENSIONS = ['.txt', '.csv', '.json']  # Example: Allow only text, CSV, and JSON files
ALLOWED_LOCATIONS = ['/safe/data/directory', './safe/data/directory'] # Example: Allow only files in these directories
MAX_FILE_SIZE = 1024 * 1024  # 1MB limit

# Initialize python-magic
try:
    MAGIC = magic.Magic(mime=True)
except magic.MagicException as e:
    logging.error(f"Failed to initialize python-magic: {e}. Content-based validation will be skipped.")
    MAGIC = None


def is_path_within_allowed_location(file_path, allowed_locations):
    """
    Checks if a file path is within any of the allowed locations.
    Handles both directory and file allowed locations.
    """
    file_path = os.path.abspath(os.path.normpath(file_path))

    for allowed_location in allowed_locations:
        allowed_location = os.path.abspath(os.path.normpath(allowed_location))

        # Check if allowed_location is a directory or a file
        if os.path.isdir(allowed_location):
            try:
                common_path = os.path.commonpath([file_path, allowed_location])
                if common_path == allowed_location:
                    return True
            except ValueError:
                # Paths have no common prefix
                pass
        elif os.path.isfile(allowed_location):
            if file_path == allowed_location:
                return True

    return False


def is_content_type_allowed(file_path, allowed_extensions):
    """
    Checks if the file content type (MIME type) matches the allowed extensions.
    Uses python-magic to determine the content type.
    """
    if MAGIC is None:
        logging.warning("Content-based validation is disabled because python-magic failed to initialize.")
        return True  # If magic is not available, allow all files (or handle differently)

    try:
        mime_type = MAGIC.from_file(file_path)
        if mime_type is None:
            logging.warning(f"Could not determine MIME type for {file_path}")
            return False

        # Map allowed extensions to MIME types (example - adjust as needed)
        extension_mime_map = {
            '.txt': 'text/plain',
            '.csv': 'text/csv',
            '.json': 'application/json'
        }

        for ext in allowed_extensions:
            if ext in extension_mime_map and extension_mime_map[ext] == mime_type:
                return True

        logging.warning(f"Content type {mime_type} is not allowed for file {file_path}")
        return False

    except Exception as e:
        logging.error(f"Error determining content type for {file_path}: {e}")
        return False


def open_file(file_path):
    """
    Safely opens a file, performing various security checks.

    :param file_path: The path to the file to open.
    :return: The file object if the file opens successfully, None otherwise.
    """

    try:
        # 1. Validate and Sanitize File Path
        if not isinstance(file_path, str):
            logging.error("Invalid file path type.  Must be a string.")
            return None

        # Normalize the path to remove redundant separators and resolve relative paths
        file_path = os.path.normpath(file_path)

        # Handle Unicode normalization
        file_path = unicodedata.normalize('NFKC', file_path)

        # Resolve symlinks BEFORE any security checks
        file_path = os.path.realpath(file_path)

        # 2. Prevent Path Traversal Attacks
        if ".." in file_path:
            logging.warning("Path traversal attempt detected: %s", file_path)
            return None

        # 3. Use Allowlists for File Extensions and Locations
        file_extension = os.path.splitext(file_path)[1].lower()
        if file_extension not in ALLOWED_EXTENSIONS:
            logging.warning("File extension not allowed: %s", file_extension)
            return None

        # Check if the file is within an allowed location
        if not is_path_within_allowed_location(file_path, ALLOWED_LOCATIONS):
            logging.warning("File location not allowed: %s", file_path)
            return None

        # 4. Implement Proper File Permissions and Access Controls
        try:
            # Check file size before opening
            file_size = os.path.getsize(file_path)
            if file_size > MAX_FILE_SIZE:
                logging.warning("File size exceeds maximum allowed: %s", file_path)
                return None

            # Check file content type
            if not is_content_type_allowed(file_path, ALLOWED_EXTENSIONS):
                logging.warning(f"File content type is not allowed: {file_path}")
                return None

            # Open the file in read-only mode ('r') immediately after checks
            file_object = open(file_path, 'r')

            # Attempt to acquire an exclusive lock (Unix-like systems)
            try:
                fcntl.flock(file_object.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)  # Non-blocking lock
            except OSError as e:
                logging.warning(f"Failed to acquire lock on file {file_path}: {e}")
                file_object.close()
                return None

            with file_object:  # Use 'with' to ensure proper closing
                # Perform operations on the file here (e.g., read data)
                # For example:
                # file_content = file_object.read()
                # print(file_content)
                logging.info("File opened successfully: %s", file_path)
                return file_object  # Return the file object

        except FileNotFoundError:
            logging.error("File not found: %s", file_path)
            return None
        except PermissionError:
            logging.error("Permission denied to open file: %s", file_path)
            return None
        except Exception as e:
            logging.error("An error occurred while opening the file: %s - %s", file_path, str(e))
            return None

    except Exception as e:
        logging.error("An unexpected error occurred: %s", str(e))
        return None


# Example Usage (with safe paths and extensions)
file_path1 = './safe/data/directory/my_data.txt'
file_path2 = '/safe/data/directory/config.json'
file_path3 = 'data.csv'  # relative path, but within allowed location
file_path4 = '../sensitive_data.txt'  # Path traversal attempt
file_path5 = '/etc/passwd'  # Outside allowed location
file_path6 = './safe/data/directory/image.png'  # Not allowed extension
file_path7 = './safe/data/directory/fake.txt' # Allowed extension, but wrong content

# Create the directory and file for testing (if they don't exist)
if not os.path.exists('./safe/data/directory'):
    os.makedirs('./safe/data/directory')
if not os.path.exists(file_path1):
    with open(file_path1, 'w') as f:
        f.write("This is some sample data.")
if not os.path.exists(file_path2):
    with open(file_path2, 'w') as f:
        f.write('{"key": "value"}')
if not os.path.exists(file_path3):
    with open(file_path3, 'w') as f:
        f.write("header1,header2\nvalue1,value2")
if not os.path.exists(file_path7):
    with open(file_path7, 'wb') as f: # Write as binary to create a PNG with a .txt extension
        f.write(b'\x89PNG\r\n\x1a\n...') # Incomplete PNG header


# Create a symlink for testing
symlink_path = './safe/data/directory/evil_link.txt'
target_path = '/etc/passwd'  # Points outside the allowed location
if not os.path.exists(symlink_path):
    try:
        os.symlink(target_path, symlink_path)
    except OSError as e:
        logging.warning(f"Failed to create symlink (may require elevated privileges): {e}")


file1 = open_file(file_path1)
if file1:
    print(f"File {file_path1} opened successfully.")
    file1.close()

file2 = open_file(file_path2)
if file2:
    print(f"File {file_path2} opened successfully.")
    file2.close()

file3 = open_file(file_path3)
if file3:
    print(f"File {file_path3} opened successfully.")
    file3.close()

file4 = open_file(file_path4)
if file4 is None:
    print(f"File {file_path4} was not opened (path traversal).")

file5 = open_file(file_path5)
if file5 is None:
    print(f"File {file_path5} was not opened (outside allowed location).")

file6 = open_file(file_path6)
if file6 is None:
    print(f"File {file_path6} was not opened (invalid extension).")

file7 = open_file(file_path7)
if file7 is None:
    print(f"File {file_path7} was not opened (invalid content).")


file8 = open_file(symlink_path)
if file8 is None:
    print(f"File {symlink_path} was not opened (symlink to outside allowed location).")

