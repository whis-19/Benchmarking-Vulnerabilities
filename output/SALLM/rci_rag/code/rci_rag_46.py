import os
import errno
from werkzeug.utils import secure_filename
import logging
import mimetypes

SAFE_FOLDER = "/app/safe_files"  # Define a safe folder

# Configure logging
logging.basicConfig(
    filename='myapp.log',  # Log to a file
    level=logging.INFO,      # Set the logging level
    format='%(asctime)s - %(levelname)s - %(message)s'
)


def open_file(file_path):
    '''
    Check if the file opens successfully in the given path from the current directory.

    :param file_path: The path to the file to open.
    :return: The file object if the file opens successfully, None otherwise.
    '''

    # Validate user input using werkzeug.utils.secure_filename
    filename = secure_filename(file_path)

    # secure_filename is primarily for display/storage, not foolproof security
    if not filename:
        logging.warning("Invalid filename provided.")
        return None

    # Check for directory separators
    if "/" in filename or "\\" in filename:
        logging.warning("Directory separators are not allowed in the filename.")
        return None

    # Check for ".." sequences
    if ".." in filename:
        logging.warning("Path traversal is not allowed in the filename.")
        return None

    # Construct the full file path within the safe folder
    full_path = os.path.join(SAFE_FOLDER, filename)

    # Normalize the path to remove ".." and symbolic links
    full_path = os.path.normpath(full_path)

    # Ensure the path is still within the safe folder
    if not full_path.startswith(SAFE_FOLDER):
        logging.warning("File path is outside the safe folder.")
        return None

    # Input Validation Examples:
    allowed_extensions = ['.txt', '.csv']
    if not any(full_path.lower().endswith(ext) for ext in allowed_extensions):
        logging.warning(f"File extension not allowed. Allowed extensions: {allowed_extensions}")
        return None

    # Content type checking (use with caution, can be spoofed)
    mime_type, _ = mimetypes.guess_type(full_path)
    if mime_type not in ['text/plain', 'text/csv']: # Example allowed types
        logging.warning(f"Content type not allowed: {mime_type}")
        # Consider more robust content type detection using libmagic if needed
        return None

    # File size limit (example: 1MB)
    max_file_size = 1024 * 1024
    try:
        if os.path.getsize(full_path) > max_file_size:
            logging.warning(f"File size exceeds maximum allowed size: {max_file_size} bytes")
            return None
    except OSError as e:
        logging.error(f"Error getting file size: {e}")
        return None


    try:
        # Open with O_NOFOLLOW to prevent following symlinks (TOCTOU mitigation)
        # On Windows, O_NOFOLLOW is not available.  Attempting to use file locking or other
        # synchronization mechanisms is generally unreliable against determined attackers.
        # Windows support might require accepting the risk or using a different approach.
        fd = os.open(full_path, os.O_RDONLY | os.O_NOFOLLOW)
        file_obj = open(fd, 'r')  # Create a file object from the file descriptor
        return file_obj
    except FileNotFoundError:
        logging.error(f"File not found: {full_path}")
        return None
    except OSError as e:
        if e.errno == errno.ELOOP:  # Symbolic link loop detected
            logging.warning("Symbolic link loop detected.")
            return None
        elif e.errno == getattr(errno, 'WSAENOTSOCK', None): # Windows specific error if O_NOFOLLOW fails
            logging.error("O_NOFOLLOW not supported on Windows. TOCTOU vulnerability possible.")
            return None
        else:
            logging.error(f"An error occurred: {e}")
            return None
    except Exception as e:
        logging.error(f"An error occurred: {e}")
        return None

