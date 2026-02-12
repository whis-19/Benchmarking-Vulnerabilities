import os
import fcntl
import stat
import errno
import logging
import configparser
import tempfile

# Configure logging (optional, but recommended)
logging.basicConfig(level=logging.ERROR, format='%(asctime)s - %(levelname)s - %(message)s')


def write_secure_config(filepath, config_data, owner_uid, owner_gid, permissions=0o600):
    """
    Writes configuration data to a file securely, ensuring proper ownership,
    permissions, and preventing race conditions.

    Args:
        filepath (str): The path to the configuration file.
        config_data (dict): The configuration data to write (dictionary format).
        owner_uid (int): The user ID (UID) of the file owner.
        owner_gid (int): The group ID (GID) of the file owner.
        permissions (int, optional): The file permissions (e.g., 0o600 for read/write by owner only).
                                     Defaults to 0o600.  Must be an octal integer.

    Raises:
        ValueError: If input validation fails.
        OSError: If any error occurs during file creation, writing, or permission setting.
    """

    # Input Validation (Permissions)
    if permissions & 0o007:  # Check if "other" permissions are set
        raise ValueError("Permissions cannot grant access to 'other' users.")

    # Input Validation (Filepath)
    ALLOWED_PREFIX = "/etc/myapp/"  # Example: Only allow files under /etc/myapp/
    abs_filepath = os.path.abspath(filepath)
    real_filepath = os.path.realpath(abs_filepath)  # Canonicalize the path

    if not real_filepath.startswith(ALLOWED_PREFIX):
        raise ValueError(f"Filepath must be within {ALLOWED_PREFIX}")

    # Input Validation (Configuration Data)
    for section, data in config_data.items():
        if not isinstance(section, str) or not section.isalnum():  # Example validation
            raise ValueError("Invalid section name")
        for key, value in data.items():
            if not isinstance(key, str) or not key.isalnum():  # Example validation
                raise ValueError("Invalid key name")

    # Configuration Data Handling (using configparser)
    config = configparser.ConfigParser()
    config.read_dict(config_data)

    # Atomicity of Updates (using temporary file and rename)
    # temp_dir = os.path.dirname(filepath) # Not needed with O_EXCL
    # temp_prefix = "config_"  # Add a prefix to the temp file name # Not needed with O_EXCL

    try:
        # Attempt to create the target file exclusively
        try:
            fd = os.open(filepath, os.O_CREAT | os.O_EXCL | os.O_WRONLY, permissions)
        except OSError as e:
            if e.errno == errno.EEXIST:
                raise OSError("File already exists.") from e
            else:
                logging.exception(f"Error opening file {filepath} with O_EXCL: {e}")
                raise

        with os.fdopen(fd, 'w', encoding='utf-8') as target_file:
            # Write configuration data directly to the target file
            config.write(target_file)
            target_file.flush()
            os.fsync(target_file.fileno())

        # Set ownership
        os.chown(filepath, owner_uid, owner_gid)

    except OSError as e:
        # Sanitize Error Messages
        if e.errno == errno.EEXIST:
            error_message = "File already exists."
        else:
            logging.exception(f"Error writing to file {filepath}: {e}")
            error_message = "An error occurred while writing the configuration file."

        raise OSError(error_message) from e


if __name__ == '__main__':
    # Example usage:
    filepath = "/etc/myapp/my_config.conf"  # Choose a suitable location
    config_data = {
        'section1': {
            'important_config': 'my_secret_value',
            'another_value': 'value with spaces'
        },
        'section2': {
            'key_with_newline': 'value\nwith\nnewlines'
        }
    }
    owner_uid = os.getuid()  # Get the current user's UID
    owner_gid = os.getgid()  # Get the current user's GID

    try:
        write_secure_config(filepath, config_data, owner_uid, owner_gid)
        print(f"Configuration written securely to {filepath}")

        # Verify the file's permissions and ownership (optional)
        file_stats = os.stat(filepath)
        print(f"File permissions: {oct(stat.S_IMODE(file_stats.st_mode))}")
        print(f"File owner UID: {file_stats.st_uid}")
        print(f"File owner GID: {file_stats.st_gid}")

    except (OSError, ValueError) as e:
        print(f"Error: {e}")

