import os
import stat
import errno
import logging
import hashlib
import re
import tempfile

# Assume these are defined elsewhere
CHECKSUM_FILE_LOCATION = "/var/checksums"  # Example, but crucial for security
CHECKSUM_FILE_EXTENSION = ".checksum"
MAX_FILENAME_LENGTH = 255  # Limit filename length to prevent DoS

def save_checksum_data(filename, bytes_read, checksum):
    """
    Saves the number of bytes read and the checksum to a file.

    Args:
        filename: The name of the original file.  Used to derive the checksum filename.
        bytes_read: The number of bytes read from the original file.  Used for verification purposes.
        checksum: The checksum of the original file.
    """

    if len(filename) > MAX_FILENAME_LENGTH:
        raise ValueError(f"Filename exceeds maximum length of {MAX_FILENAME_LENGTH}")

    # Sanitize filename before hashing (defense in depth)
    sanitized_filename = re.sub(r'[^\w\._-]', '_', filename)  # Replace non-alphanumeric with underscore

    # Secure filename generation using a hash
    filename_hash = hashlib.sha256(sanitized_filename.encode('utf-8')).hexdigest()
    checksum_filename = filename_hash + CHECKSUM_FILE_EXTENSION
    checksum_filepath = os.path.join(CHECKSUM_FILE_LOCATION, checksum_filename)

    try:
        # Ensure the checksum directory exists
        try:
            os.makedirs(CHECKSUM_FILE_LOCATION, exist_ok=True)
        except OSError as e:
            logging.error(f"Failed to create checksum directory: {e}")
            raise

        # Set restrictive umask
        original_umask = os.umask(0o077)  # Remove group/other permissions

        # Create a temporary file in the same directory
        with tempfile.NamedTemporaryFile(mode='w', dir=CHECKSUM_FILE_LOCATION, delete=False) as tmp_file:
            tmp_file.write(f"Bytes Read: {bytes_read}\n")
            tmp_file.write(f"Checksum: {checksum}\n")
            tmp_file_path = tmp_file.name

        # Atomically rename the temporary file to the final checksum file
        os.rename(tmp_file_path, checksum_filepath)


    except OSError as e:
        if e.errno == errno.EACCES:
            logging.error(f"Permission denied saving checksum: {e}")
        elif e.errno == errno.ENOSPC:
            logging.error(f"Disk full saving checksum: {e}")
        else:
            logging.error(f"OS error saving checksum: {e}")
        raise from e  # Re-raise, preserving the original traceback
    finally:
        # Restore original umask
        os.umask(original_umask)
        # Ensure the temporary file is deleted if an error occurred
        if 'tmp_file_path' in locals() and os.path.exists(tmp_file_path):
            try:
                os.remove(tmp_file_path)
            except OSError as e:
                logging.error(f"Failed to remove temporary file: {e}")

    logging.info("Checksum data saved successfully.") # Avoid logging the full path

