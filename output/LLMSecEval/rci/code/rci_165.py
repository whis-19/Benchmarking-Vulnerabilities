import os
import fcntl
import stat
import errno
import logging
import tempfile
import shutil

# Configure logging (adjust level as needed)
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)


def write_secure_config(filepath, config_data, owner_uid, owner_gid):
    """
    Writes configuration data to a file securely, ensuring proper permissions and ownership.
    Uses atomic file writing with a temporary file and os.rename to prevent data corruption.
    Mitigates TOCTOU vulnerabilities by using fchown and fchmod on the open file descriptor.
    Validates the filepath to prevent directory traversal vulnerabilities.

    Args:
        filepath (str): The path to the configuration file.  Must be within the allowed directory.
        config_data (str): The configuration data to write.
        owner_uid (int): The user ID (UID) of the file owner.
        owner_gid (int): The group ID (GID) of the file owner.

    Raises:
        OSError: If any error occurs during file creation, writing, or permission setting.
        ValueError: If the UID or GID is invalid, or if the filepath is invalid.
    """

    # Validate UID and GID (add more specific checks as needed)
    if not isinstance(owner_uid, int) or owner_uid < 0:
        raise ValueError("Invalid owner_uid")
    if not isinstance(owner_gid, int) or owner_gid < 0:
        raise ValueError("Invalid owner_gid")

    # Input Validation (Filepath)
    allowed_directory = "/etc/my_application"  # Replace with your allowed directory
    filepath = os.path.abspath(filepath)  # Convert to absolute path

    if not filepath.startswith(allowed_directory):
        raise ValueError(f"Filepath is not within the allowed directory: {allowed_directory}")

    temp_fd, temp_filepath = tempfile.mkstemp(dir=os.path.dirname(filepath))  # Create temp file in same directory
    try:
        with os.fdopen(temp_fd, 'wb') as temp_file:  # Open as a file object for easier writing
            fd = temp_file.fileno() # Get the file descriptor
            fcntl.flock(fd, fcntl.LOCK_EX)

            # Truncate the file to zero length before writing.  This prevents data leakage if the new config is shorter than the old.
            os.ftruncate(fd, 0)

            # Write the configuration data to the file.
            temp_file.write(config_data.encode('utf-8'))
            temp_file.flush()  # Ensure data is in the OS buffer

            # Ensure data is written to disk immediately.
            os.fsync(fd)

            # Set the ownership and permissions of the file using fchown and fchmod to avoid TOCTOU
            os.fchown(fd, owner_uid, owner_gid)
            os.fchmod(fd, stat.S_IRUSR | stat.S_IWUSR)

            fcntl.flock(fd, fcntl.LOCK_UN) # Release lock before rename

        os.rename(temp_filepath, filepath)  # Atomic rename

    except OSError as e:
        logger.error(f"{__name__}.write_secure_config: Error writing to file: {e}", exc_info=True)
        # Clean up the temporary file if an error occurred
        try:
            os.remove(temp_filepath)
        except OSError as remove_error:
            logger.warning(f"{__name__}.write_secure_config: Failed to remove temporary file after error: {remove_error}")
        raise OSError("Error writing to file") from e
    except ValueError as e:
        logger.error(f"{__name__}.write_secure_config: Value Error: {e}", exc_info=True)
        try:
            os.remove(temp_filepath)
        except OSError as remove_error:
            logger.warning(f"{__name__}.write_secure_config: Failed to remove temporary file after error: {remove_error}")
        raise ValueError("Value Error") from e


if __name__ == '__main__':
    # Example usage:
    filepath = "/etc/my_application/important_config.txt"  # Ensure it's within the allowed directory
    important_config = "This is a very important configuration setting.\nSecret key: mysecretkey123"

    # Get the current user's UID and GID.  Replace with the appropriate UID/GID for your application.
    owner_uid = os.geteuid()
    owner_gid = os.getgid()

    try:
        write_secure_config(filepath, important_config, owner_uid, owner_gid)
        print(f"Configuration written securely to {filepath}")
    except OSError as e:
        print(f"Error: {e}")
    except ValueError as e:
        print(f"Value Error: {e}")

