import os
import stat
import fcntl
import logging
import tempfile
import shutil

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def secure_write_config(config_data, file_path):
    """
    Securely writes configuration data to a file, preventing path traversal,
    limiting file size, and setting appropriate permissions.

    Args:
        config_data (str): The configuration data to write.
        file_path (str): The path to the configuration file.
    """

    # Security: Validate and sanitize file path
    if not isinstance(file_path, str):
        raise TypeError("File path must be a string.")

    if ".." in file_path:
        raise ValueError("Path traversal detected.  '..' is not allowed in file paths.")

    if file_path.count(".") > 1:
        raise ValueError("Invalid file path. Only one '.' allowed.")

    # Security: Allowlist for file extensions (example: only allow .conf files)
    if not file_path.endswith(".conf"):
        raise ValueError("Invalid file extension. Only '.conf' files are allowed.")

    # Security: Allowlist for file locations (example: only allow files in /etc/myapp/)
    # This example assumes a configuration directory exists.  Adjust as needed.
    ALLOWED_PATH_PREFIX = "/etc/myapp/"
    if not file_path.startswith(ALLOWED_PATH_PREFIX):
        raise ValueError(f"Invalid file location.  Must be within {ALLOWED_PATH_PREFIX}")

    # Create the directory if it doesn't exist
    os.makedirs(os.path.dirname(file_path), exist_ok=True)

    # Security: Use a temporary file for writing to prevent data corruption
    # and ensure atomicity.
    try:
        temp_file = tempfile.NamedTemporaryFile(delete=False, mode='w', dir=os.path.dirname(file_path), suffix=".tmp")
        temp_file_name = temp_file.name

        try:
            # Write the configuration data to the temporary file
            temp_file.write(config_data)
            temp_file.flush()  # Ensure all data is written
            os.fsync(temp_file.fileno()) # Ensure data is written to disk
        except Exception as e:
            logging.error(f"Error writing to temporary file: {e}")
            raise
        finally:
            temp_file.close()

        # Security: Set file permissions before renaming
        try:
            os.chmod(temp_file_name, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH)  # Read/write for owner, read for group/others
        except OSError as e:
            logging.error(f"Error setting file permissions: {e}")
            os.remove(temp_file_name) # Clean up the temp file
            raise

        # Security: Atomic rename to replace the original file
        try:
            os.replace(temp_file_name, file_path)  # Atomic operation
        except OSError as e:
            logging.error(f"Error renaming temporary file: {e}")
            os.remove(temp_file_name) # Clean up the temp file
            raise

        logging.info(f"Successfully wrote configuration to {file_path}")

    except Exception as e:
        logging.error(f"Failed to write configuration to {file_path}: {e}")
        raise

    # Security: Limit file size (example: 1MB limit)
    MAX_FILE_SIZE = 1024 * 1024  # 1MB
    if os.path.getsize(file_path) > MAX_FILE_SIZE:
        logging.warning(f"File size exceeds maximum limit of {MAX_FILE_SIZE} bytes.  Consider truncating or rotating the file.")
        # Optionally, truncate the file:
        with open(file_path, 'r+') as f:
            f.truncate(MAX_FILE_SIZE)

# Example usage:
if __name__ == "__main__":
    config_data = "important_config_data=some_value\nother_setting=another_value"
    file_path = "/etc/myapp/myconfig.conf"  # Example path within the allowed location

    try:
        secure_write_config(config_data, file_path)
        print(f"Configuration written successfully to {file_path}")
    except ValueError as e:
        print(f"Error: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

