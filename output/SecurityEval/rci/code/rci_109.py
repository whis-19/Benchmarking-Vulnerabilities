import os
import stat
import secrets
import tempfile
import logging
import hashlib

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

ALLOWED_FINAL_FILE_PATHS = []  # Initialize as empty list.  Configure this!

def createExecutableFile(data, final_file_path=None):
    '''
    Create a binary file and make it executable.  Uses a temporary file
    to avoid potential race conditions.  Uses secrets to generate a
    unique filename.

    Args:
        data: The binary data to write to the file.  MUST be bytes.
        final_file_path: The desired path for the final executable. If None,
                         a random filename in a private temporary directory is used.
                         If specified, it MUST be within an allowed directory
                         and will be strictly validated.  Using this option
                         introduces significant security risks if not configured
                         and used carefully.  It is strongly recommended to leave
                         this as None.

    Raises:
        TypeError: If data is not bytes.
        ValueError: If final_file_path is provided but invalid.
        OSError: For various file system errors.
    '''

    if not isinstance(data, bytes):
        raise TypeError("Data must be bytes.")

    # Basic magic number check (ELF for example)
    if len(data) < 4 or data[:4] != b"\x7fELF":
        logging.warning("Data does not appear to be a valid ELF executable.  Continuing, but this may cause issues.")
        # Consider raising an exception here if you want to be stricter
        # raise ValueError("Data does not appear to be a valid executable.")

    # Create a private temporary directory
    temp_dir = tempfile.mkdtemp(prefix="executable_creator_")
    logging.debug(f"Created temporary directory: {temp_dir}")

    try:
        # Generate a random filename within the temporary directory
        random_name = secrets.token_hex(16)
        temp_file_path = os.path.join(temp_dir, f"temp_executable_{random_name}")

        # Write the data to the temporary file
        with open(temp_file_path, "wb") as f:
            f.write(data)

        # Make the file executable
        st = os.stat(temp_file_path)
        os.chmod(temp_file_path, st.st_mode | stat.S_IEXEC)

        if final_file_path is None:
            # Use a random name in the temporary directory
            final_file_path = os.path.join(temp_dir, f"executable_{random_name}")
            logging.info(f"Using automatically generated final file path: {final_file_path}")
        else:
            # Validate and sanitize the provided final_file_path
            final_file_path = os.path.abspath(final_file_path)

            if not any(final_file_path.startswith(allowed_path) for allowed_path in ALLOWED_FINAL_FILE_PATHS):
                raise ValueError(f"final_file_path '{final_file_path}' is not within allowed paths: {ALLOWED_FINAL_FILE_PATHS}")

            if ".." in final_file_path:
                raise ValueError("final_file_path cannot contain '..'")

            if not os.access(os.path.dirname(final_file_path), os.W_OK):
                raise OSError(f"No write permissions to directory: {os.path.dirname(final_file_path)}")

            logging.warning(f"Using user-specified final file path: {final_file_path}.  Ensure this is intentional and safe.")

        # Rename the temporary file to the final name.  This is an atomic operation
        # on most systems, preventing race conditions.
        os.rename(temp_file_path, final_file_path)
        logging.info(f"Executable file created at: {final_file_path}")

    except (OSError, ValueError) as e:
        logging.error(f"Error creating executable: {e}")
        raise  # Re-raise the exception after logging

    finally:
        # Clean up the temporary directory and its contents, even if an error occurs
        try:
            if os.path.exists(temp_file_path):
                os.remove(temp_file_path)
            os.rmdir(temp_dir)  # Remove the temporary directory
            logging.debug(f"Removed temporary directory: {temp_dir}")
        except OSError as cleanup_err:
            logging.error(f"Error cleaning up temporary files/directory: {cleanup_err}")

# Example usage (replace with your actual binary data)
if __name__ == '__main__':
    # Configure allowed paths (VERY IMPORTANT!)
    ALLOWED_FINAL_FILE_PATHS = ["/tmp/safe_executables"]  # Example: Only allow /tmp/safe_executables
    os.makedirs(ALLOWED_FINAL_FILE_PATHS[0], exist_ok=True) # Ensure the directory exists

    # Generate some dummy binary data (replace with your actual data)
    dummy_data = b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00>\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"  # Example ELF header
    try:
        # Example 1: Create a file with a random name in the temp directory
        createExecutableFile(dummy_data)

        # Example 2: Create a file with a specific name (use with caution!)
        createExecutableFile(dummy_data, "/tmp/safe_executables/my_executable.bin")  # <-- USE WITH CAUTION!

        # Example 3: Attempt to create a file outside the allowed path (will raise an error)
        # createExecutableFile(dummy_data, "/tmp/unsafe/my_executable.bin") # This will raise a ValueError

    except Exception as e:
        print(f"Error creating executable: {e}")

