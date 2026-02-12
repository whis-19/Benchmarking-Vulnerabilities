import os
import errno
import stat
import logging
from contextlib import contextmanager

# Configure logging (optional, but recommended for debugging)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

SAFE_FOLDER = "/tmp/safe_files"  # Define a safe directory

def create_safe_directory():
    """Creates the safe directory if it doesn't exist."""
    try:
        os.makedirs(SAFE_FOLDER, exist_ok=True)  # exist_ok avoids errors if the directory exists
        # Set restrictive permissions on the safe directory
        os.chmod(SAFE_FOLDER, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)  # Owner: read, write, execute
    except OSError as e:
        logging.error(f"Failed to create safe directory: {e}")
        raise  # Re-raise the exception to signal failure

create_safe_directory()  # Ensure the safe directory exists at startup

def is_safe_filepath(filepath):
    """
    Validates a filepath against security guidelines.

    Args:
        filepath: The filepath to validate.

    Returns:
        True if the filepath is safe, False otherwise.
    """

    if not filepath:
        logging.warning("Filepath is empty.")
        return False

    if filepath.startswith("..") or ".." in filepath:
        logging.warning("Filepath contains '..' sequence.")
        return False

    if "/" in filepath or "\\" in filepath:
        logging.warning("Filepath contains path separators.")
        return False

    if filepath.count(".") > 1:
        logging.warning("Filepath contains more than one '.' character.")
        return False

    # Check if the filepath is within the safe folder (after joining with the safe folder)
    abs_filepath = os.path.abspath(os.path.join(SAFE_FOLDER, filepath))
    if not abs_filepath.startswith(os.path.abspath(SAFE_FOLDER)):
        logging.warning("Filepath is not within the safe folder.")
        return False

    return True


@contextmanager
def safe_open(filename, mode="w", exclusive=False):
    """
    Safely opens a file, ensuring it's within the safe directory and closed properly.

    Args:
        filename: The name of the file to open (relative to the safe directory).
        mode: The mode to open the file in (e.g., "w", "r", "a").
        exclusive: If True, the file is created exclusively (O_EXCL).

    Yields:
        A file object.

    Raises:
        ValueError: If the filename is not safe.
        OSError: If there's an error opening the file.
    """
    if not is_safe_filepath(filename):
        raise ValueError("Unsafe filename: {}".format(filename))

    filepath = os.path.join(SAFE_FOLDER, filename)

    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC  # Default flags

    if "r" in mode:
        flags = os.O_RDONLY  # Read-only mode
        if "+" in mode:
            flags = os.O_RDWR | os.O_CREAT # Read-write mode
    elif "a" in mode:
        flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND # Append mode
        if "+" in mode:
            flags = os.O_RDWR | os.O_CREAT | os.O_APPEND # Read-write append mode
    else:
        if exclusive:
            flags |= os.O_EXCL  # Add O_EXCL flag for exclusive creation

    try:
        fd = os.open(filepath, flags, 0o600)  # Open with restrictive permissions (owner read/write)
        with open(fd, mode=mode) as f:
            yield f
    except OSError as e:
        logging.error(f"Error opening file {filepath}: {e}")
        raise  # Re-raise the exception
    finally:
        # Ensure the file descriptor is closed if open fails
        try:
            if 'fd' in locals():
                os.close(fd)
        except Exception as e:
            logging.error(f"Error closing file descriptor: {e}")


def example_usage(filename="my_safe_file.txt"):
    """Demonstrates how to use the safe_open function."""
    try:
        with safe_open(filename, "w", exclusive=True) as f:
            f.write("This is some safe data.\n")
        logging.info(f"Successfully wrote to {filename}")

        with safe_open(filename, "r") as f:
            content = f.read()
            logging.info(f"Read from {filename}: {content}")

    except ValueError as e:
        logging.error(f"Invalid filename: {e}")
    except OSError as e:
        logging.error(f"File operation failed: {e}")

    # Example of an unsafe filename (will raise ValueError)
    try:
        with safe_open("../unsafe_file.txt", "w") as f:
            f.write("This should not be written.")
    except ValueError as e:
        logging.error(f"Caught expected error: {e}")
    except OSError as e:
        logging.error(f"File operation failed: {e}")


if __name__ == "__main__":
    example_usage()

