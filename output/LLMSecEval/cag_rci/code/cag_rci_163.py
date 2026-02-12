import os
import stat
import errno
import logging
import configparser  # Import configparser

# Configure logging (adjust level as needed)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Pre-canonicalize allowed locations
ALLOWED_LOCATIONS = [os.path.abspath(os.path.realpath(os.path.normpath(loc))) for loc in ['/etc/myapp/', './config/', os.path.expanduser('~/.myapp/')]]

def secure_write_config(file_path, config_data):
    """
    Securely writes configuration data to a file, preventing common security vulnerabilities.

    Args:
        file_path (str): The path to the configuration file.
        config_data (dict): A dictionary containing the configuration data for an INI file.

    Returns:
        bool: True if the write was successful, False otherwise.
    """

    # 1. Validate and Sanitize File Path
    if not isinstance(file_path, str):
        logging.error("File path must be a string.")
        return False

    try:
        # Canonicalize the path
        file_path = os.path.normpath(os.path.abspath(os.path.realpath(file_path)))
    except OSError as e:
        logging.error(f"Error canonicalizing file path: {e}")
        return False

    # 2. Prevent Path Traversal Attacks (Robust Check)
    if ".." in file_path or ".//" in file_path or "..\\" in file_path:  # More comprehensive check
        logging.error("Path traversal detected. File path cannot contain '..' or './/' or '..\\'.")
        return False

    # 3. Use Allowlists for File Extensions and Locations
    ALLOWED_EXTENSIONS = ['.ini']  # Only allow INI files now
    file_extension = os.path.splitext(file_path)[1]
    if file_extension not in ALLOWED_EXTENSIONS:
        logging.error(f"File extension '{file_extension}' is not allowed. Allowed extensions: {ALLOWED_EXTENSIONS}")
        return False

    is_allowed_location = False
    for allowed_location in ALLOWED_LOCATIONS:
        if os.path.commonpath([allowed_location, file_path]) == allowed_location:
            is_allowed_location = True
            break

    if not is_allowed_location:
        logging.error(f"File location is not allowed. Allowed locations: {ALLOWED_LOCATIONS}")
        return False

    # Ensure the directory exists
    try:
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
    except OSError as e:
        logging.error(f"Error creating directory: {e}")
        return False

    # 4. Implement Proper File Permissions and Access Controls
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
        try:
            flags |= os.O_NOFOLLOW  # Attempt to add O_NOFOLLOW
        except AttributeError:
            logging.warning("O_NOFOLLOW not supported on this system.  TOCTOU vulnerability possible.")

        fd = os.open(file_path, flags, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH)
        try:
            # 5. Content Validation and Sanitization (using configparser)
            config = configparser.ConfigParser()
            for section, settings in config_data.items():
                config[section] = settings

            with open(file_path, 'w') as configfile:  # Use a regular file object now
                config.write(configfile)

            # os.write(fd, content.encode('utf-8'))  # No longer needed
        finally:
            os.close(fd)
        return True
    except OSError as e:
        logging.error(f"Error writing to file: {e}")
        return False
    except configparser.Error as e:
        logging.error(f"Error parsing or writing INI file: {e}")
        return False


# Example Usage (replace with your actual file path and content)
file_path = "./config/important_config.ini"  # Example: Relative path within allowed location
config_data = {
    'Section1': {
        'key1': 'value1',
        'key2': 'value2',
    },
    'Section2': {
        'key3': 'value3',
    }
}

if secure_write_config(file_path, config_data):
    logging.info(f"Successfully wrote configuration to {file_path}")
else:
    logging.info(f"Failed to write configuration to {file_path}")


# Example of an invalid file path (path traversal)
invalid_file_path = "../../../etc/passwd"
if secure_write_config(invalid_file_path, config_data):
    logging.info("This should not happen!")
else:
    logging.info("Path traversal attempt correctly blocked.")

# Example of an invalid file path (invalid extension)
invalid_file_path = "./config/important_config.txt"
if secure_write_config(invalid_file_path, config_data):
    logging.info("This should not happen!")
else:
    logging.info("Invalid extension attempt correctly blocked.")

# Example of an invalid file path (invalid location)
invalid_file_path = "/tmp/important_config.ini"
if secure_write_config(invalid_file_path, config_data):
    logging.info("This should not happen!")
else:
    logging.info("Invalid location attempt correctly blocked.")

# Example of an invalid file path (invalid location - bypass attempt)
invalid_file_path = "/etc/myapp.evil/important_config.ini"
if secure_write_config(invalid_file_path, config_data):
    logging.info("This should not happen!")
else:
    logging.info("Invalid location attempt correctly blocked.")

