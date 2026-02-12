import hashlib
import os
import secrets
import stat
from typing import Tuple
from werkzeug.utils import secure_filename

# Constants
MAX_FILE_SIZE = 1024 * 1024  # 1MB limit for input file
LOG_FILE_SIZE_LIMIT = 1024 * 100  # 100KB limit for log file
OUTPUT_FILE_SIZE_LIMIT = 1024 * 100  # 100KB limit for output file
ALLOWED_FILE_EXTENSIONS = {'txt', 'csv', 'dat'}  # Example allowlist

def calculate_checksum_and_save(input_filepath: str, output_filepath: str, log_filepath: str) -> None:
    """
    Reads a file, calculates its checksum, and saves the checksum and byte count to another file.

    Args:
        input_filepath: Path to the input file.
        output_filepath: Path to the output file where checksum and byte count will be saved.
        log_filepath: Path to the log file.
    """

    # Validate filepaths
    if not is_valid_filepath(input_filepath):
        log_message(log_filepath, f"Invalid input filepath: {input_filepath}")
        raise ValueError("Invalid input filepath.")

    if not is_valid_filepath(output_filepath):
        log_message(log_filepath, f"Invalid output filepath: {output_filepath}")
        raise ValueError("Invalid output filepath.")

    if not is_valid_filepath(log_filepath):
        log_message(log_filepath, f"Invalid log filepath: {log_filepath}")
        raise ValueError("Invalid log filepath.")

    # Validate input file extension
    if not is_allowed_file_extension(input_filepath):
        log_message(log_filepath, f"Invalid input file extension for: {input_filepath}")
        raise ValueError("Invalid input file extension.")

    try:
        # Read file content
        buffer, bytes_read = read_file(input_filepath, log_filepath)

        # Calculate checksum
        checksum = calculate_checksum(buffer)

        # Check if buffer is empty
        is_empty = checksum == 0

        # Save checksum and byte count
        save_results(output_filepath, bytes_read, checksum, is_empty, log_filepath)

    except Exception as e:
        log_message(log_filepath, f"An error occurred: {e}")
        raise

def is_valid_filepath(filepath: str) -> bool:
    """
    Validates a filepath to prevent directory traversal and other security issues.
    """
    if not filepath:
        return False

    if filepath.count('.') > 1:
        return False

    filename = secure_filename(os.path.basename(filepath))
    if filename != os.path.basename(filepath):
        return False

    normalized_path = os.path.normpath(filepath)
    if ".." in normalized_path:
        return False

    if os.path.isabs(normalized_path):
        return False

    return True

def is_allowed_file_extension(filepath: str) -> bool:
    """
    Checks if the file extension is in the allowlist.
    """
    extension = filepath.split('.')[-1].lower()
    return extension in ALLOWED_FILE_EXTENSIONS

def read_file(filepath: str, log_filepath: str) -> Tuple[bytes, int]:
    """
    Reads the content of a file into a buffer, limiting the file size.
    """
    try:
        file_size = os.path.getsize(filepath)
        if file_size > MAX_FILE_SIZE:
            log_message(log_filepath, f"File size exceeds the limit: {file_size} > {MAX_FILE_SIZE}")
            raise ValueError("File size exceeds the limit.")

        with open(filepath, "rb") as f:
            buffer = f.read()
        return buffer, len(buffer)
    except FileNotFoundError:
        log_message(log_filepath, f"File not found: {filepath}")
        raise
    except Exception as e:
        log_message(log_filepath, f"Error reading file: {e}")
        raise

def calculate_checksum(buffer: bytes) -> int:
    """
    Calculates the checksum of a buffer using SHA-256 with a random salt.
    """
    salt = secrets.token_bytes(16)  # Generate a random salt
    salted_buffer = salt + buffer
    hash_object = hashlib.sha256(salted_buffer)
    hex_dig = hash_object.hexdigest()
    return int(hex_dig, 16)

def save_results(filepath: str, bytes_read: int, checksum: int, is_empty: bool, log_filepath: str) -> None:
    """
    Saves the number of bytes read and the checksum to a file, limiting the file size.
    """
    try:
        output_string = f"Bytes Read: {bytes_read}\nChecksum: {checksum}\nEmpty: {is_empty}\n"

        # Check file size before writing
        if os.path.exists(filepath) and os.path.getsize(filepath) + len(output_string.encode('utf-8')) > OUTPUT_FILE_SIZE_LIMIT:
            log_message(log_filepath, f"Output file size limit exceeded for: {filepath}")
            raise ValueError("Output file size limit exceeded.")

        with open(filepath, "w") as f:
            f.write(output_string)

        # Restrict file permissions (read/write for owner only)
        os.chmod(filepath, stat.S_IRUSR | stat.S_IWUSR)

    except Exception as e:
        log_message(log_filepath, f"Error saving results: {e}")
        raise

def log_message(filepath: str, message: str) -> None:
    """
    Logs a message to a file, limiting the file size.
    """
    try:
        # Check file size before writing
        if os.path.exists(filepath) and os.path.getsize(filepath) + len(message.encode('utf-8')) > LOG_FILE_SIZE_LIMIT:
            print("Log file size limit exceeded.  Skipping log entry.") # Print to console as a fallback
            return # Skip logging to prevent errors

        with open(filepath, "a") as f:
            f.write(f"{datetime.datetime.now()} - {message}\n")
    except Exception as e:
        print(f"Error writing to log file: {e}") # Print to console as a fallback

import datetime

if __name__ == '__main__':
    # Example Usage (replace with actual filepaths)
    input_file = "input.txt"
    output_file = "output.txt"
    log_file = "log.txt"

    # Create a dummy input file for testing
    with open(input_file, "w") as f:
        f.write("This is a test file.")

    try:
        calculate_checksum_and_save(input_file, output_file, log_file)
        print(f"Checksum and byte count saved to {output_file}")
    except ValueError as e:
        print(f"Error: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

