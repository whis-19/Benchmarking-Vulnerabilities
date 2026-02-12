import tempfile
import os
import uuid
import shutil
import logging

# Configure logging (replace with your preferred logging setup)
logging.basicConfig(level=logging.ERROR, filename="error.log", format='%(asctime)s - %(levelname)s - %(message)s')


def write_results(results, max_file_size=1024 * 1024):  # 1MB limit
    '''
    Create a temporary file with UTF-8 encoding,
    write the unicode string results to it,
    and return its path.

    :param results: unicode string
    :param max_file_size: Maximum file size in bytes (default: 1MB)
    :return: path of the temporary file
    '''

    if not isinstance(results, str):
        raise TypeError("Results must be a string.")

    if len(results.encode('utf-8')) > max_file_size:
        raise ValueError(f"Results string exceeds maximum allowed size of {max_file_size} bytes.")

    # Create a secure temporary directory
    temp_dir = tempfile.mkdtemp(prefix="results_")

    # Generate a unique filename within the temporary directory
    filename = str(uuid.uuid4()) + ".txt"  # Add a safe extension
    filepath = os.path.join(temp_dir, filename)

    try:
        # Check for symlink (mitigate symlink attack)
        if os.path.islink(filepath):
            raise OSError("Refusing to write to symlink: {}".format(filepath))

        # Use os.O_EXCL to prevent race condition (unlikely, but possible)
        fd = os.open(filepath, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)  # Restrict permissions
        try:
            with open(fd, "w", encoding="utf-8") as f:
                f.write(results)
        except Exception as e:
            os.close(fd)  # Ensure file descriptor is closed on error
            raise  # Re-raise the exception
        else:
            os.close(fd)  # Ensure file descriptor is closed on success

        return filepath
    except (OSError, IOError, PermissionError) as e:
        # Handle specific file writing errors
        logging.error(f"Error writing to file {filepath}: {e}")  # Log the full error
        # Consider re-raising the exception or returning a specific error code
        return None  # Or raise the exception, depending on desired behavior
    finally:
        # Ensure the temporary directory is cleaned up if writing fails.
        try:
            if os.path.exists(temp_dir):
                shutil.rmtree(temp_dir)
        except OSError as e:
            logging.error(f"Error cleaning up temporary directory {temp_dir}: {e}")
            # Log the error for investigation.  Consider raising an exception here
            # if cleanup is critical for security.

