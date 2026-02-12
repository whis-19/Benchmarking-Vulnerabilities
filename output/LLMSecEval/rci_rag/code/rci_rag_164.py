import os
import errno
import stat
import logging
from contextlib import contextmanager
from typing import Optional
import re

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

SAFE_FOLDER = "/tmp/safe_files"  # Define a safe folder
MAX_PATH_LENGTH = 255

def secure_file_creation(filename: str, content: str, overwrite: bool = False) -> None:
    """
    Creates a file securely, preventing common file-related vulnerabilities.

    Args:
        filename: The name of the file to create.
        content: The content to write to the file.
        overwrite: Whether to overwrite the file if it exists.  Defaults to False.

    Raises:
        ValueError: If the filename is invalid or contains unsafe characters.
        OSError: If there are issues creating or writing to the file.
    """

    # 1. Filename Validation
    if not is_filename_safe(filename):
        logging.error(f"Invalid filename: {filename}")
        raise ValueError("Invalid filename: Filename contains unsafe characters or sequences.")

    # 2. Path Confinement
    filepath = os.path.join(SAFE_FOLDER, filename)

    # 2a. Check Path Length
    if len(filepath) > MAX_PATH_LENGTH:
        logging.error(f"Path length exceeds maximum allowed: {filepath}")
        raise ValueError(f"Path length exceeds maximum allowed: {MAX_PATH_LENGTH}")

    # Create the safe folder if it doesn't exist and set permissions
    try:
        os.makedirs(SAFE_FOLDER, exist_ok=True)
        os.chmod(SAFE_FOLDER, 0o700)  # Ensure restrictive permissions on the folder
    except OSError as e:
        logging.error(f"Failed to create/set permissions on safe folder: {e}")
        raise OSError(f"Failed to create safe folder: {e}") from e

    # 3.  Handle Overwrite/Create Exclusively
    flags = os.O_WRONLY | os.O_CREAT
    if overwrite:
        flags |= os.O_TRUNC
    else:
        flags |= os.O_EXCL  # Fail if the file exists

    # 4. Secure File Opening and Writing
    fd: Optional[int] = None  # Initialize fd to None
    try:
        fd = os.open(filepath, flags, 0o600)  # Open with restrictive permissions
        try:
            with os.fdopen(fd, 'w') as f:
                f.write(content)
                logging.info(f"File '{filename}' created/updated successfully.") # Log success
        except OSError as e:
            logging.error(f"Failed to write to file '{filename}': {e}")
            raise OSError(f"Failed to write to file: {e}") from e
    except OSError as e:
        if e.errno == errno.EEXIST:
            logging.error(f"File '{filename}' already exists and overwrite is disabled.")
            raise OSError("File already exists and overwrite is disabled.") from e
        else:
            logging.error(f"Failed to open file '{filename}': {e}")
            raise OSError(f"Failed to open file: {e}") from e
    finally:
        if fd is not None:  # Check if fd was successfully opened
            try:
                os.close(fd)
            except OSError as e:
                logging.warning(f"Failed to close file descriptor for '{filename}': {e}")


def is_filename_safe(filename: str) -> bool:
    """
    Validates a filename to prevent path traversal and other vulnerabilities.
    Uses a whitelist approach.

    Args:
        filename: The filename to validate.

    Returns:
        True if the filename is safe, False otherwise.
    """

    if not isinstance(filename, str) or not filename:
        return False

    if not re.match(r"^[a-zA-Z0-9._-]+$", filename):  # Whitelist: alphanumeric, ., _, -
        return False

    if len(filename) > 255:
        return False

    # Check for potentially problematic filenames like "." or ".."
    if filename in (".", ".."):
        return False

    return True


# Example Usage:
if __name__ == "__main__":
    try:
        secure_file_creation("my_safe_file.txt", "This is some safe content.", overwrite=False)
        print("File created successfully.")

        secure_file_creation("my_safe_file.txt", "Overwriting the file.", overwrite=True)
        print("File overwritten successfully.")

        # Example of an unsafe filename (will raise an exception)
        try:
            secure_file_creation("../unsafe_file.txt", "This will fail.")
        except ValueError as e:
            print(f"Expected Error: {e}")

        # Example of long filename
        try:
            long_filename = "a" * 300 + ".txt"
            secure_file_creation(long_filename, "This will fail due to length.")
        except ValueError as e:
            print(f"Expected Error: {e}")


    except OSError as e:
        print(f"Error: {e}")
    except ValueError as e:
        print(f"Error: {e}")

