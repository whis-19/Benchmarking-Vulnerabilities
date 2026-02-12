import os
import fcntl
import stat
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def secure_write_config(file_path, content):
    """
    Securely creates or writes to a configuration file with restricted permissions.

    Args:
        file_path (str): The path to the configuration file.
        content (str): The content to write to the file.

    Returns:
        bool: True if the operation was successful, False otherwise.
    """

    # 1. Validate and sanitize file paths
    if not isinstance(file_path, str):
        logging.error("File path must be a string.")
        return False

    # 2. Prevent path traversal attacks
    if ".." in file_path:
        logging.error("Path traversal detected in file path.")
        return False

    # 14. Prevent multiple "." characters
    if file_path.count(".") > 1:
        logging.error("Multiple '.' characters detected in file path.")
        return False

    # 3. Use allowlists for file extensions and locations (Example: only allow .conf files in /etc/app/)
    if not file_path.endswith(".conf") or not file_path.startswith("/etc/app/"):
        logging.error("Invalid file extension or location.")
        return False

    try:
        # 4. Implement proper file permissions and access controls
        # O_CREAT: Create the file if it does not exist.
        # O_WRONLY: Open the file for writing only.
        # O_TRUNC: Truncate the file to zero length if it exists.
        fd = os.open(file_path, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH)

        # Get the maximum file size from the environment, or default to 1MB
        max_file_size = int(os.environ.get("MAX_FILE_SIZE", 1024 * 1024))

        # Write the content to the file
        bytes_written = os.write(fd, content.encode('utf-8'))

        # 13. Prevent files from growing without any limit
        if bytes_written > max_file_size:
            logging.error(f"File size exceeds maximum allowed size of {max_file_size} bytes.")
            os.ftruncate(fd, max_file_size)  # Truncate the file to the maximum size
            bytes_written = max_file_size

        # Ensure all data is written to disk
        os.fsync(fd)

        logging.info(f"Successfully wrote {bytes_written} bytes to {file_path}")
        return True

    except OSError as e:
        logging.error(f"Error writing to file: {e}")
        return False
    finally:
        # 6. Ensure that an opened file it is always closed on exiting the method.
        if 'fd' in locals():
            os.close(fd)

if __name__ == '__main__':
    # Example usage:
    file_path = "/etc/app/important_config.conf"  # Example allowed path
    config_content = "This is a very important configuration setting.\nAnother important setting."

    if secure_write_config(file_path, config_content):
        print("Configuration file written successfully.")
    else:
        print("Failed to write configuration file.")

    # Example of an invalid file path (path traversal)
    invalid_file_path = "../../../tmp/config.conf"
    if secure_write_config(invalid_file_path, "test"):
        print("Configuration file written successfully.")
    else:
        print("Failed to write configuration file.")

    # Example of an invalid file path (invalid extension)
    invalid_file_path = "/etc/app/config.txt"
    if secure_write_config(invalid_file_path, "test"):
        print("Configuration file written successfully.")
    else:
        print("Failed to write configuration file.")

