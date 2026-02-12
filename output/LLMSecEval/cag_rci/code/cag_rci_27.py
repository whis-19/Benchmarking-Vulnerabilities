import os
import stat
import fcntl  # For O_NOFOLLOW
import logging
import re

# Configuration - Define safe directory, allowed extensions, and user/group
SAFE_DIRECTORY = "/path/to/safe/directory"  # Replace with your safe directory
ALLOWED_EXTENSIONS = [".txt", ".pdf", ".csv"]  # Allowed file extensions
ALLOWED_LOCATIONS = ["/path/to/safe/directory", "/path/to/another/safe/directory"] # Allowed locations
ALLOWED_LOCATIONS = [os.path.abspath(path) for path in ALLOWED_LOCATIONS] # Convert to absolute paths for consistency

# User and group to run the file access as (optional, but recommended)
TARGET_USER = "nobody"  # Replace with a less privileged user
TARGET_GROUP = "nogroup"  # Replace with a less privileged group

MAX_FILENAME_LENGTH = 255  # Maximum filename length

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def is_path_safe(filepath, safe_directory, allowed_locations):
    """
    Checks if a file path is within the allowed safe directories.
    """
    try:
        real_path = os.path.realpath(filepath)
        for allowed_location in allowed_locations:
            if real_path.startswith(allowed_location):
                return True
        logging.warning(f"Path {filepath} resolves to {real_path} which is not in allowed locations.")
        return False
    except OSError as e:
        logging.error(f"OSError in is_path_safe: {e} for path {filepath}")
        return False


def is_extension_allowed(filename, allowed_extensions):
    """
    Checks if the file extension is in the list of allowed extensions.
    """
    _, ext = os.path.splitext(filename)
    return ext.lower() in allowed_extensions


def read_safe_file(filename):
    """
    Reads a file from the safe directory after validating the path and extension.

    Args:
        filename (str): The name of the file to read.

    Returns:
        str: The content of the file, or None if an error occurred.
    """

    filepath = os.path.join(SAFE_DIRECTORY, filename)

    # Input Sanitization
    if len(filename) > MAX_FILENAME_LENGTH:
        logging.warning(f"Filename too long: {filename}")
        return None

    if not re.match(r"^[a-zA-Z0-9._-]+$", filename):
        logging.warning(f"Invalid filename format: {filename}")
        return None

    if not is_path_safe(filepath, SAFE_DIRECTORY, ALLOWED_LOCATIONS):
        logging.warning(f"Unsafe file path: {filepath}")
        return None

    if not is_extension_allowed(filename, ALLOWED_EXTENSIONS):
        logging.warning(f"Invalid file extension: {filename}")
        return None

    try:
        # Change user and group (if configured) - drop privileges
        if TARGET_USER and TARGET_GROUP:
            import pwd
            import grp

            try:
                uid = pwd.getpwnam(TARGET_USER).pw_uid
                gid = grp.getgrnam(TARGET_GROUP).gr_gid
                os.setgroups([]) # Clear supplementary groups
                os.setgid(gid)
                os.setuid(uid)
            except KeyError as e:
                logging.error(f"User or group not found: {e}")
                return None  # Important: Return immediately if privilege drop fails
            except OSError as e:
                logging.error(f"Failed to change user/group: {e}")
                return None  # Important: Return immediately if privilege drop fails

        # Open and read the file
        try:
            fd = os.open(filepath, os.O_RDONLY | fcntl.O_NOFOLLOW)
            with open(fd, "rb") as f:
                content = f.read()
            return content.decode('utf-8', errors='replace') # Decode to string, replacing errors
        except FileNotFoundError:
            logging.warning(f"File not found: {filepath}")
            return None
        except IOError as e:
            logging.error(f"Error reading file: {e}")
            return None
        except Exception as e:
            logging.exception(f"Unexpected error reading file: {filepath}") # Log the full exception
            return None

    except FileNotFoundError:
        logging.warning(f"File not found: {filepath}")
        return None
    except IOError as e:
        logging.error(f"Error reading file: {e}")
        return None
    except Exception as e:
        logging.exception(f"Unexpected error: {e}")
        return None

