import os
import time
import logging
from werkzeug.utils import secure_filename

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Constants
SAFE_FOLDER = "safe_data_storage"  # Define a safe folder
MAX_FILE_SIZE = 1024 * 1024  # 1MB limit
OUTPUT_ENCODING = "utf-8"

def foo():
    """
    Simulates an external source providing basename and data.
    In a real application, this would be replaced with actual data retrieval.
    """
    return "./", "This is some sample data."


def is_valid_filename(filename):
    """
    Validates the filename against common security vulnerabilities.
    """
    if not filename:
        return False

    if filename.startswith('.'):
        return False

    if ".." in filename:
        return False

    if "/" in filename or "\\" in filename:
        return False

    if len(filename) > 255:  # Limit filename length
        return False

    # Allowlist of allowed characters (alphanumeric, underscore, hyphen, period)
    allowed_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-"
    for char in filename:
        if char not in allowed_chars:
            return False

    return True


def dataSorting():
    """
    Continuously takes (basename, data) key-value pair from foo() function and sorts it,
    writing the data to a file within a safe directory.
    """

    try:
        os.makedirs(SAFE_FOLDER, exist_ok=True)  # Create the safe folder if it doesn't exist

        basename, data = foo()  # Get data from the external source (foo)

        # Validate basename (although foo() is internal, we still validate for safety)
        if not basename or basename == ".":
            logging.error("Invalid basename received: %s", basename)
            return

        # Validate data
        if not isinstance(data, str):
            logging.error("Invalid data type received. Expected string, got %s", type(data))
            return

        # Sanitize the filename using werkzeug.secure_filename
        filename = secure_filename(basename)

        # Additional filename validation
        if not is_valid_filename(filename):
            logging.error("Invalid filename: %s", filename)
            return

        filepath = os.path.join(SAFE_FOLDER, filename)

        # Check if the file already exists.  If so, append a timestamp to the filename.
        if os.path.exists(filepath):
            name, ext = os.path.splitext(filename)
            timestamp = str(int(time.time()))
            filename = f"{name}_{timestamp}{ext}"
            filepath = os.path.join(SAFE_FOLDER, filename)


        # Write data to the file with size limit and proper encoding
        try:
            with open(filepath, "w", encoding=OUTPUT_ENCODING) as f:
                if len(data.encode(OUTPUT_ENCODING)) > MAX_FILE_SIZE:
                    logging.error("Data size exceeds maximum allowed size (%d bytes).", MAX_FILE_SIZE)
                    return

                f.write(data)
            logging.info("Data successfully written to file: %s", filepath)

        except Exception as e:
            logging.error("Error writing to file: %s", e)

    except Exception as e:
        logging.error("An unexpected error occurred: %s", e)


if __name__ == "__main__":
    dataSorting()

