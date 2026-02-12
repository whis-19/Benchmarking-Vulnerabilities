import hashlib
import os
import secrets
import stat
import logging
from typing import Tuple
from werkzeug.utils import secure_filename
import hmac
import datetime
import unicodedata

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Constants for file size limits and permissions
MAX_FILE_SIZE = 1024 * 1024  # 1MB limit
LOG_FILE_SIZE_LIMIT = 1024 * 100  # 100KB limit for log file
RESTRICTED_FILE_PERMISSIONS = 0o600  # Owner read/write only
# HMAC_KEY = secrets.token_bytes(32)  # Key for HMAC, stored securely
HMAC_KEY = os.environ.get("HMAC_KEY")
if not HMAC_KEY:
    logging.critical("HMAC_KEY environment variable not set!")
    raise ValueError("HMAC_KEY environment variable not set!")  # Or exit the program

HMAC_KEY = HMAC_KEY.encode('utf-8') # Ensure it's bytes


def calculate_checksum(data: bytes, salt: bytes) -> str:
    """Calculates the SHA-256 checksum of the data with a salt and HMAC.

    Args:
        data: The bytes to calculate the checksum for.
        salt: A random salt to add to the data before hashing.

    Returns:
        The hexadecimal representation of the SHA-256 checksum.
    """
    salted_data = salt + data
    # Use HMAC to mitigate timing attacks
    hashed_data = hmac.new(HMAC_KEY, salted_data, hashlib.sha256).digest()
    return hashed_data.hex()


def read_file_into_buffer(filepath: str) -> Tuple[bytes, int]:
    """Reads the contents of a file into a buffer, limiting the file size.

    Args:
        filepath: The path to the file to read.

    Returns:
        A tuple containing the bytes read and the number of bytes read.
        Returns (b'', 0) if the file is too large or an error occurs.
    """
    try:
        # Validate filepath using werkzeug.secure_filename
        filename = os.path.basename(filepath)
        filename = unicodedata.normalize('NFKC', filename)
        filename = secure_filename(filename)

        if not filename:
            logging.error("Invalid filename.")
            return b'', 0

        # Construct the full path safely
        base_dir = os.path.dirname(filepath)
        if base_dir:
            # Normalize the base directory path
            normalized_path = os.path.normpath(base_dir)
            if ".." in normalized_path or not os.path.isabs(normalized_path):
                logging.error("Invalid filepath.")
                return b'', 0

        full_filepath = os.path.join(base_dir, filename)

        # Check file size before reading
        file_size = os.path.getsize(full_filepath)
        if file_size > MAX_FILE_SIZE:
            logging.error(f"File size exceeds limit ({MAX_FILE_SIZE} bytes).")
            return b'', 0

        with open(full_filepath, "rb") as f:
            buffer = f.read()
            num_bytes_read = len(buffer)
        return buffer, num_bytes_read

    except FileNotFoundError:
        logging.error(f"File not found: {filepath}")
        return b'', 0
    except PermissionError as e:
        logging.error(f"Permission error reading file: {e}")
        return b'', 0
    except OSError as e:
        logging.error(f"Could not read file: {e}")
        return b'', 0


def write_checksum_to_file(
    output_filepath: str, num_bytes: int, checksum: str, salt: bytes
) -> None:
    """Writes the number of bytes read and the checksum to a file.

    Args:
        output_filepath: The path to the output file.
        num_bytes: The number of bytes read.
        checksum: The checksum of the data.
        salt: The salt used to generate the checksum.
    """
    try:
        # Validate filepath using werkzeug.secure_filename
        filename = os.path.basename(output_filepath)
        filename = unicodedata.normalize('NFKC', filename)
        filename = secure_filename(filename)

        if not filename:
            logging.error("Invalid filename.")
            return

        # Construct the full path safely
        base_dir = os.path.dirname(output_filepath)
        if base_dir:
            # Normalize the base directory path
            normalized_path = os.path.normpath(base_dir)
            if ".." in normalized_path or not os.path.isabs(normalized_path):
                logging.error("Invalid filepath.")
                return

        full_output_filepath = os.path.join(base_dir, filename)

        # Check if the file exists and rotate if it exceeds the limit
        if os.path.exists(full_output_filepath) and os.path.getsize(full_output_filepath) > LOG_FILE_SIZE_LIMIT:
            logging.warning("Log file size limit reached. Rotating log file.")
            log_rotation(full_output_filepath)

        with open(full_output_filepath, "a") as f:
            f.write(f"Bytes Read: {num_bytes}\n")
            f.write(f"Checksum: {checksum}\n")
            f.write(f"Salt: {salt.hex()}\n")  # Store the salt in hex format

        # Restrict file permissions
        os.chmod(full_output_filepath, RESTRICTED_FILE_PERMISSIONS)

    except PermissionError as e:
        logging.error(f"Permission error writing to file: {e}")
    except OSError as e:
        logging.error(f"Could not write to file: {e}")


def log_rotation(log_filepath: str) -> None:
    """Rotates the log file by renaming the current log file to a backup and creating a new empty log file."""
    try:
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_filepath = f"{log_filepath}.bak.{timestamp}"

        # Rename the current log file to the backup filename
        os.rename(log_filepath, backup_filepath)
        # Create a new empty log file
        with open(log_filepath, "w") as f:
            pass  # Create an empty file
        logging.info(f"Log file rotated. Old log saved as {backup_filepath}")
    except OSError as e:
        logging.error(f"Error rotating log file: {e}")

def main(input_filepath: str, output_filepath: str) -> None:
    """Main function to read a file, calculate the checksum, and write the results.

    Args:
        input_filepath: The path to the input file.
        output_filepath: The path to the output file.
    """
    buffer, num_bytes_read = read_file_into_buffer(input_filepath)

    if num_bytes_read == 0:
        logging.warning("Buffer is empty or an error occurred during file reading.")
        checksum = "N/A"  # Indicate no checksum was calculated
        salt = b'' # No salt needed if no checksum
    else:
        salt = secrets.token_bytes(16)  # Generate a random salt
        checksum = calculate_checksum(buffer, salt)

    write_checksum_to_file(output_filepath, num_bytes_read, checksum, salt)


if __name__ == "__main__":
    # Example usage:
    input_file = "input.txt"  # Replace with your input file
    output_file = "output.log"  # Replace with your output file

    # Create a dummy input file for testing
    with open(input_file, "w") as f:
        f.write("This is a test file with unicode characters: éàçüö")

    main(input_file, output_file)

