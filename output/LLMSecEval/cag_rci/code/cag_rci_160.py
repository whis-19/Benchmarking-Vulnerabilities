import os
import stat
import logging
import configparser
import re
import pwd  # For user name lookup
import grp  # For group name lookup

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Configuration (Read from a config file)
config = configparser.ConfigParser()
config.read('file_io.conf')

SAFE_DIRECTORY = config.get('paths', 'safe_directory')
ALLOWED_EXTENSIONS = set(config.get('files', 'allowed_extensions').split(','))
ALLOWED_LOCATIONS = set(config.get('paths', 'allowed_locations').split(','))
ALLOWED_LOCATIONS = {os.path.abspath(path) for path in ALLOWED_LOCATIONS}

# Validate SAFE_DIRECTORY
if not os.path.isdir(SAFE_DIRECTORY):
    logging.error(f"SAFE_DIRECTORY '{SAFE_DIRECTORY}' is not a valid directory.")
    raise ValueError("Invalid SAFE_DIRECTORY configuration.")
if not os.access(SAFE_DIRECTORY, os.W_OK):
    logging.error(f"SAFE_DIRECTORY '{SAFE_DIRECTORY}' is not writable.")
    raise ValueError("Invalid SAFE_DIRECTORY configuration: Not writable.")

# Validate ALLOWED_LOCATIONS
for location in ALLOWED_LOCATIONS:
    if not os.path.isdir(location):
        logging.error(f"ALLOWED_LOCATION '{location}' is not a valid directory.")
        raise ValueError("Invalid ALLOWED_LOCATIONS configuration.")
    # Prevent overly broad entries (e.g., "/")
    if location == "/":
        logging.error("ALLOWED_LOCATIONS cannot contain '/'.")
        raise ValueError("Invalid ALLOWED_LOCATIONS configuration: Contains root directory.")

# Ensure SAFE_DIRECTORY is within ALLOWED_LOCATIONS
if not any(SAFE_DIRECTORY.startswith(location) for location in ALLOWED_LOCATIONS):
    logging.error(f"SAFE_DIRECTORY '{SAFE_DIRECTORY}' is not within ALLOWED_LOCATIONS.")
    raise ValueError("Invalid SAFE_DIRECTORY configuration: Not within allowed locations.")

# Ensure file_io.conf has permissions 600 (read/write only by the owner)

# Filename regex: Prevents filenames starting with a dot, limits base filename to 1-64 characters, requires an extension, and allows alphanumeric characters, underscores, and hyphens.
FILENAME_REGEX = r"^(?!\.)[a-zA-Z0-9_-]{1,64}\.[a-zA-Z0-9]+$"

def is_path_safe(filepath, allowed_locations):
    """
    Checks if the given filepath is safe to access.
    """
    try:
        abs_path = os.path.abspath(filepath)
        abs_path = os.path.normpath(abs_path)
        real_path = os.path.realpath(abs_path)  # Resolve symlinks

        # Re-check after resolving symlinks
        if not any(real_path.startswith(location) for location in allowed_locations):
            logging.warning(f"Path is not within allowed locations: {real_path} not in {allowed_locations}")
            return False

        return True

    except ValueError:
        logging.error("Invalid path.")
        return False
    except OSError as e:
        logging.error(f"OS Error during path validation: {e}")
        return False


def read_safe_file(filename, user_id, group_id, max_file_size=1024 * 1024):
    """
    Reads a file from the safe directory, ensuring security.
    """

    filepath = os.path.join(SAFE_DIRECTORY, filename)

    # Validate the filename
    if not filename:
        logging.warning("Filename cannot be empty.")
        return None

    if not re.match(FILENAME_REGEX, filename):
        logging.warning(f"Invalid filename: {filename}")
        return None

    # Validate file extension
    _, file_extension = os.path.splitext(filename)
    if file_extension.lower() not in ALLOWED_EXTENSIONS:
        logging.warning(f"File extension '{file_extension}' not allowed.")
        return None

    # Check if the path is safe
    if not is_path_safe(filepath, ALLOWED_LOCATIONS):
        logging.warning("Path is not safe.")
        return None

    try:
        # Check if the file exists
        if not os.path.exists(filepath):
            logging.warning(f"File not found: {filepath}")
            return None

        # Check if the file is a regular file
        if not os.path.isfile(filepath):
            logging.warning(f"Not a regular file: {filepath}")
            return None

        # Check file size
        file_size = os.path.getsize(filepath)
        if file_size > max_file_size:
            logging.warning(f"File size exceeds maximum allowed size: {file_size} > {max_file_size}")
            return None

        # Get inode before opening
        try:
            initial_inode = os.stat(filepath).st_ino
        except OSError as e:
            logging.error(f"Error getting initial inode: {e}")
            return None

        # Read the file content
        with open(filepath, "r") as f:
            content = f.read()

        # Check inode after reading
        try:
            current_inode = os.stat(filepath).st_ino
            # TOCTOU mitigation: Inode comparison.  Note: Inodes can be reused, so this is not a foolproof solution.
            if current_inode != initial_inode:
                logging.warning("Possible TOCTOU attack detected: File replaced after opening.")
                return None
        except OSError as e:
            logging.error(f"Error getting current inode: {e}")
            return None

        # Validate user and group IDs
        try:
            user_id = int(user_id)
            group_id = int(group_id)
        except ValueError:
            logging.error("Invalid user_id or group_id: Must be integers.")
            return None

        # Set file ownership (mandatory)
        try:
            os.chown(filepath, user_id, group_id)
        except OSError as e:
            logging.error(f"Error changing file ownership: {e}")
            return None

        # Set file permissions (read-only for owner, group, and others)
        try:
            os.chmod(filepath, stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
        except OSError as e:
            logging.error(f"Error changing file permissions: {e}")
            return None

        return content

    except FileNotFoundError:
        logging.warning(f"File not found: {filepath}")
        return None
    except PermissionError:
        logging.warning(f"Permission denied to read file: {filepath}")
        return None
    except OSError as e:  # Catch OSError for file system related errors
        logging.error(f"OS Error: {e}")
        return None
    except Exception as e:
        logging.exception(f"An unexpected error occurred: {e}")  # Log the full exception traceback
        return None

# Example usage:
if __name__ == "__main__":
    # Create a dummy file for testing (ensure the directory exists)
    test_file = "test.txt"
    test_file_path = os.path.join(SAFE_DIRECTORY, test_file)

    # Ensure the safe directory exists
    if not os.path.exists(SAFE_DIRECTORY):
        os.makedirs(SAFE_DIRECTORY)

    with open(test_file_path, "w") as f:
        f.write("This is a test file.")

    # Read user and group IDs from the configuration file
    user_id = config.get('user', 'user_id')
    group_id = config.get('user', 'group_id')

    # Example usage with a valid file
    content = read_safe_file(test_file, user_id=user_id, group_id=group_id)
    if content:
        print("File content:")
        print(content)

    # Example usage with an invalid file extension
    content = read_safe_file("test.exe", user_id=user_id, group_id=group_id)
    if content is None:
        print("File with invalid extension not read.")

    # Example usage with a path traversal attempt
    content = read_safe_file("../../../etc/passwd", user_id=user_id, group_id=group_id)
    if content is None:
        print("Path traversal attempt prevented.")

    # Note: Disk quotas and rate limiting should be implemented at the system level to prevent DoS attacks.

    # Clean up the test file
    os.remove(test_file_path)

