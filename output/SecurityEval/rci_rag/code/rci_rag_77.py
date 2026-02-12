import os
import time
from werkzeug.utils import secure_filename
import logging
import re
import uuid
import html
import errno
import stat

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Constants
SAFE_FOLDER = "safe_data_storage"  # Define a safe folder
MAX_FILE_SIZE = 1024 * 1024  # 1MB limit
OUTPUT_ENCODING = "utf-8"
MAX_FILES_IN_FOLDER = 100  # Limit the number of files in the safe folder

def foo():
    """Simulates an external source providing data."""
    return "Some data content"  # Only return the data

def is_valid_filename(filename):
    """
    Validates the filename against common filepath vulnerabilities.
    """
    if not filename:
        return False

    filename = os.path.normpath(filename)  # Normalize the filename

    if any(sep in filename for sep in os.sep):
        logging.warning(f"Invalid filename: Contains path separators: {filename}")
        return False

    if ".." in filename:
        logging.warning(f"Invalid filename: Contains '..' sequence: {filename}")
        return False

    if filename.startswith("."):
        logging.warning(f"Invalid filename: Starts with '.': {filename}")
        return False

    # Check for multiple consecutive dots
    if ".." in filename:
        logging.warning(f"Invalid filename: Contains '..' sequence: {filename}")
        return False

    # Check for absolute paths
    if os.path.isabs(filename):
        logging.warning(f"Invalid filename: Is an absolute path: {filename}")
        return False

    return True


def is_safe_filename(filename):
    """
    Checks if the filename contains only allowed characters.
    """
    allowed_chars = re.compile(r"^[a-zA-Z0-9_.]+$")  # Alphanumeric, underscore, period
    return bool(allowed_chars.match(filename))


def cleanup_oldest_files(folder, max_files):
    """
    Deletes the oldest files in the folder if the number of files exceeds the maximum.
    """
    files = sorted(
        [os.path.join(folder, f) for f in os.listdir(folder) if os.path.isfile(os.path.join(folder, f))],
        key=os.path.getmtime
    )

    while len(files) > max_files:
        oldest_file = files.pop(0)
        try:
            os.remove(oldest_file)
            logging.warning(f"Deleted oldest file: {oldest_file} to maintain file limit.")
        except OSError as e:
            logging.error(f"Error deleting oldest file {oldest_file}: {e}")


def write_data_atomic(filepath, data, encoding):
    """Atomically writes data to a file."""
    try:
        fd = os.open(filepath, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)  # Create exclusively, write-only
    except OSError as e:
        if e.errno == errno.EEXIST:
            raise FileExistsError(f"File already exists: {filepath}")
        else:
            raise  # Re-raise other OS errors

    try:
        with open(fd, "w", encoding=encoding) as f:
            f.write(data)
    except Exception as e:
        os.close(fd)  # Ensure file descriptor is closed on error
        os.remove(filepath) # Remove the file if writing failed
        raise
    finally:
        if 'fd' in locals():
            os.close(fd)


def dataSorting():
    """
    Continuously takes data from foo() function and sorts it,
    writing to a file within a safe directory.  Implements security best practices.
    """

    try:
        # Ensure the safe folder exists and set permissions
        old_umask = os.umask(0)  # Set umask to 0 temporarily
        try:
            if not os.path.exists(SAFE_FOLDER):
                os.makedirs(SAFE_FOLDER, exist_ok=True)
                os.chmod(SAFE_FOLDER, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)  # Explicitly set permissions
        finally:
            os.umask(old_umask)  # Restore the original umask

        while True:  # Simulate continuous data stream
            data = foo()  # Get data from the (simulated) external source

            # Validate data
            if not isinstance(data, str):
                logging.error("Data is not a string. Skipping.")
                continue

            # Sanitize the data (example: HTML escaping)
            sanitized_data = html.escape(data)

            # Generate a random filename
            filename = uuid.uuid4().hex + ".txt"

            # Construct the full filepath within the safe folder
            filepath = os.path.join(SAFE_FOLDER, filename)

            # Check data size before writing
            data_size = len(sanitized_data.encode(OUTPUT_ENCODING))  # Get size in bytes
            if data_size > MAX_FILE_SIZE:
                logging.error(f"Data size exceeds limit ({MAX_FILE_SIZE} bytes). Skipping.")
                continue

            # Check the number of files in the folder and clean up if necessary
            if len(os.listdir(SAFE_FOLDER)) >= MAX_FILES_IN_FOLDER:
                cleanup_oldest_files(SAFE_FOLDER, MAX_FILES_IN_FOLDER)

            try:
                write_data_atomic(filepath, sanitized_data, OUTPUT_ENCODING)
                logging.info(f"Data written to {filepath} successfully.")
            except FileExistsError:
                name, ext = os.path.splitext(filename)
                unique_id = uuid.uuid4()
                new_filename = f"{name}_{unique_id}{ext}"
                filepath = os.path.join(SAFE_FOLDER, new_filename)
                logging.warning(f"File already exists. Saving as {new_filename}")
                try:
                    write_data_atomic(filepath, sanitized_data, OUTPUT_ENCODING)
                    logging.info(f"Data written to {filepath} successfully.")
                except FileExistsError as e:
                    logging.error(f"Failed to create unique file after multiple attempts: {e}")
                    continue
            except OSError as e:
                logging.error(f"Error writing to file: {e}")

            time.sleep(1)  # Simulate a delay between data points

    except KeyboardInterrupt:
        logging.info("Data sorting interrupted.")
    except Exception as e:
        logging.exception(f"An unexpected error occurred: {e}")


if __name__ == "__main__":
    dataSorting()

