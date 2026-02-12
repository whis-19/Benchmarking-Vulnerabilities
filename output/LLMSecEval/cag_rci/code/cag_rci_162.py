import os
import stat
import logging
import contextlib
import json  # Example: For JSON validation

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

    Args:
        file_path (str): The path to the configuration file.
        content (str): The content to write to the file.
        allowed_extensions (list): A list of allowed file extensions (e.g., [".conf", ".ini"]).
        allowed_directories (list): A list of allowed parent directories (e.g., ["/etc/my_app"]).

    Returns:
        bool: True if the write was successful, False otherwise.
    """

    # 1. Validate and Sanitize File Path
    if not isinstance(file_path, str):
        logging.error("File path must be a string.")
        return False

    # 2. Prevent Path Traversal Attacks
    absolute_path = os.path.abspath(file_path)
    normalized_path = os.path.normpath(absolute_path)

    real_path = os.path.realpath(normalized_path)  # Get the real path

    if not any(real_path.lower().startswith(allowed_dir.lower()) for allowed_dir in allowed_directories):
        logging.error(f"Real file path '{real_path}' is not in an allowed directory.")
        return False

    # 3. Use Allowlists for File Extensions and Locations
    file_name, file_extension = os.path.splitext(file_path)
    if file_extension.lower() not in (ext.lower() for ext in allowed_extensions):
        logging.error(f"File extension '{file_extension}' is not allowed.")
        return False

    # 4. Validate Content (JSON Example)
    try:
        json.loads(content)  # Basic JSON validation
    except json.JSONDecodeError as e:
        logging.error(f"Invalid JSON content: {e}")
        return False

    # 5. Implement Proper File Permissions and Access Controls
    file_descriptor = None
    try:
        # Open the file with restricted permissions (read/write for owner only)
        # Using os.open to set permissions during file creation
        with set_umask(0):  # Temporarily set umask to 0
            file_descriptor = os.open(normalized_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_EXCL, stat.S_IRUSR | stat.S_IWUSR)  # 0o600
            with open(file_descriptor, 'w') as f:
                f.write(content)
        return True

    except FileExistsError:
        logging.error(f"File already exists: {normalized_path}")
        return False
    except OSError as e:
        logging.error(f"Error writing to file: {e} (errno: {e.errno})")
        return False
    finally:
        if file_descriptor is not None:
            os.close(file_descriptor)


# Example Usage (replace with your actual file path and content)
allowed_extensions = [".conf", ".config", ".ini", ".txt"]  # Example allowed extensions
allowed_directories = [os.path.normpath(d) for d in ["/etc/my_app", "/opt/my_app/config"]]  # Example allowed directories

file_path = "/etc/my_app/important_config.conf"  # Example path within the allowlist
config_content = '{"key": "value"}'  # Example JSON content

if write_to_config_file(file_path, config_content, allowed_extensions, allowed_directories):
    logging.info("Configuration file written successfully.")
else:
    logging.error("Failed to write configuration file.")

