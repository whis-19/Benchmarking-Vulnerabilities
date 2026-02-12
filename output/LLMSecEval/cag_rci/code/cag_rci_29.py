import os
import stat
import logging
import contextlib
import configparser  # Example for INI file validation

# Configure logging (example)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

@contextlib.contextmanager
def set_umask(mask):
    """Context manager for temporarily setting the umask."""
    old_mask = os.umask(mask)
    try:
        yield
    finally:
        os.umask(old_mask)


def write_to_config_file(file_path, content, allowed_extensions, allowed_directories):
    """
    Writes content to a configuration file, ensuring security best practices.
    """

    # 1. Validate and Sanitize File Path
    if not isinstance(file_path, str):
        logging.error("File path must be a string.")
        return False

    # 2. Prevent Path Traversal Attacks
    absolute_path = os.path.abspath(file_path)
    normalized_path = os.path.normpath(absolute_path)

    if not any(normalized_path.lower().startswith(allowed_dir.lower()) for allowed_dir in allowed_directories):
        logging.error(f"File path '{normalized_path}' is not in an allowed directory.")
        return False

    # 3. Use Allowlists for File Extensions and Locations
    file_name, file_extension = os.path.splitext(file_path)
    if file_extension.lower() not in (ext.lower() for ext in allowed_extensions):
        logging.error(f"File extension '{file_extension}' is not allowed.")
        return False

    # 4. Content Validation (CRITICAL!)
    def is_valid_ini_content(content):
        try:
            config = configparser.ConfigParser()
            config.read_string(content)
            # Add further validation based on your specific requirements
            # For example, check for required sections or options
            return True
        except configparser.Error as e:
            logging.error(f"Invalid INI content: {e}")
            return False

    if not is_valid_ini_content(content):
        logging.error("Invalid configuration content.")
        return False


    # 5. Implement Proper File Permissions and Access Controls
    try:
        with set_umask(0):
            file_descriptor = os.open(normalized_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_EXCL, stat.S_IRUSR | stat.S_IWUSR)
            with open(file_descriptor, 'w') as f:
                f.write(content)
        os.close(file_descriptor)
        return True

    except FileExistsError:
        logging.error(f"File already exists: {normalized_path}")
        return False
    except OSError as e:
        logging.error(f"Error writing to file: {e} - Errno: {e.errno}")
        return False


# Example Usage
allowed_extensions = [".conf", ".config", ".ini", ".txt"]
allowed_directories = ["/etc/my_app", "/opt/my_app/config"]

file_path = "/etc/my_app/important_config.ini"
config_content = "[section]\nkey = value"  # Valid INI content

if write_to_config_file(file_path, config_content, allowed_extensions, allowed_directories):
    logging.info("Configuration file written successfully.")
else:
    logging.error("Failed to write configuration file.")

