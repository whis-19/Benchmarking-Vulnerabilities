import os
import logging

# Configure logging (replace with your desired configuration)
logging.basicConfig(level=logging.INFO, filename="safe_file_reader.log", format='%(asctime)s - %(levelname)s - %(message)s')

def read_safe_file(filename):
    """
    Reads a file from the /safe/ directory.  Improved security.

    Args:
        filename: The name of the file to read.

    Returns:
        The content of the file as a string, or None if the file does not exist or an error occurs.
    """

    safe_directory = "/safe/"
    max_file_size = 1024 * 1024  # 1MB limit

    # 0. Check for symlinks *before* normalization
    if os.path.islink(filename):
        logging.error(f"Attempted to read symbolic link: {filename}")
        print("Error: Symbolic links are not allowed.")
        return None

    # 1. Input Validation and Normalization:
    filepath = os.path.join(safe_directory, filename)
    filepath = os.path.normpath(os.path.abspath(filepath))

    if os.path.ismount(filepath):
        logging.error(f"UNC path detected: {filepath}")
        print("Error: UNC paths are not allowed.")
        return None

    if not filepath.startswith(safe_directory):
        logging.error(f"Path traversal detected: {filepath}")
        print("Error: Path traversal detected.")
        return None

    # 2. Check File Size
    try:
        file_size = os.path.getsize(filepath)
        if file_size > max_file_size:
            logging.error(f"File too large: {filepath} ({file_size} bytes)")
            print("Error: File too large.")
            return None
    except OSError as e:
        logging.error(f"Could not get file size for '{filepath}': {e}")
        print(f"Error: Could not get file size for '{filepath}'.")
        return None

    # 3. Read the file content (with TOCTOU mitigation and O_NOFOLLOW)
    try:
        # Use os.open with O_NOFOLLOW to prevent symlink traversal
        fd = os.open(filepath, os.O_RDONLY | os.O_NOFOLLOW)
        with open(fd, "r") as f:  # Create a file object from the file descriptor
            content = ""
            chunk_size = 4096  # 4KB chunk size
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                content += chunk
        return content
    except FileNotFoundError:
        logging.error(f"File not found: {filepath}")
        print(f"Error: File '{filepath}' not found.")
        return None
    except PermissionError:
        logging.error(f"Permission denied to read '{filepath}'")
        print(f"Error: Permission denied to read '{filepath}'.")
        return None
    except OSError as e:  # Catch OSError for O_NOFOLLOW related errors
        logging.error(f"OSError while opening/reading '{filepath}': {e}")
        print(f"Error: An I/O error occurred while reading '{filepath}'.")
        return None
    except IOError as e:
        logging.error(f"IOError while reading '{filepath}': {e}")
        print(f"Error: An I/O error occurred while reading '{filepath}'.")
        return None
    except Exception as e:
        logging.exception("An unexpected error occurred.")  # Log the full traceback
        print("An unexpected error occurred.")
        return None

