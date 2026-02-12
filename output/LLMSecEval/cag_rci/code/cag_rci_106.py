import os
import stat
import logging

# --- Configuration ---
ENCRYPTED_FILES_DIR = os.path.abspath("encrypted_files")
ALLOWED_FILE_LOCATIONS = [ENCRYPTED_FILES_DIR]  # Use absolute paths
ALLOWED_FILE_EXTENSIONS = [".txt"]
TARGET_FILENAME = "secret.txt"
FILE_PERMISSION_MODE = stat.S_IRUSR | stat.S_IWUSR  # Read/Write for owner only

# --- Logging Setup ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s')


def is_path_safe(filepath: str) -> bool:
    """Validates the filepath against path traversal attacks and allowed locations."""
    abs_path = os.path.abspath(os.path.normpath(filepath))  # Normalize and get absolute path

    is_safe = any(abs_path.startswith(loc) for loc in ALLOWED_FILE_LOCATIONS)

    if not is_safe:
        logging.error(f"Filepath '{filepath}' is not within allowed locations: {ALLOWED_FILE_LOCATIONS}")
        return False

    return True


def create_and_write_file(filepath: str, data: bytes, file_permission_mode: int) -> None:
    """Creates a file, writes data to it, and sets restrictive permissions."""

    if not is_path_safe(filepath):
        logging.error(f"Unsafe filepath: {filepath}")
        raise ValueError("Unsafe filepath.")

    try:
        if os.path.exists(filepath):
            logging.error(f"File '{filepath}' already exists: {filepath}")
            raise FileExistsError(f"File '{filepath}' already exists.")

        # Set umask before creating the file
        old_umask = os.umask(0o077)  # Read/write/execute for owner only

        try:
            with open(filepath, "wb") as f:  # Use "wb" for writing bytes
                f.write(data)

            # Set restrictive file permissions
            os.chmod(filepath, file_permission_mode)

            # Verify permissions
            stat_info = os.stat(filepath)
            if stat_info.st_mode & 0o777 != file_permission_mode:
                logging.warning(f"File permissions not set as expected. Expected: {file_permission_mode:o}, Actual: {stat_info.st_mode & 0o777:o}")

            logging.info(f"File '{filepath}' created, written, and permissions set successfully.")

        finally:
            # Restore the original umask
            os.umask(old_umask)

    except OSError as e:
        logging.exception(f"Error writing to file '{filepath}': {e}")  # Log the exception with traceback
        raise
    except FileExistsError as e:
        logging.error(f"File exists error: {e}")
        raise
    except Exception as e:
        logging.critical(f"An unexpected error occurred while creating/writing file '{filepath}': {e}", exc_info=True)  # Log with traceback
        raise

