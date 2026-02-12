import os
import stat
import secrets
import logging
from werkzeug.utils import secure_filename

# --- Configuration ---
SAFE_FOLDER = "/opt/app/config"  # Restrict file creation to this directory
ALLOWED_EXTENSIONS = {"cfg"}  # Only allow .cfg files
MAX_FILE_SIZE = 1024 * 1024  # 1MB limit
CONFIG_FILE_NAME = "important_config.cfg"
LOG_FILE = "/opt/app/logs/app.log"

# --- Logging Setup ---
logging.basicConfig(filename=LOG_FILE, level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')


def create_secure_config_file(config_data):
    """
    Creates a configuration file with restricted permissions and security checks.

    Args:
        config_data (dict):  A dictionary containing configuration data.  Sensitive
                             data should be encrypted/hashed *before* being passed in.
    """

    # --- Input Validation and Sanitization ---
    if not isinstance(config_data, dict):
        logging.error("Invalid config_data type.  Must be a dictionary.")
        raise ValueError("config_data must be a dictionary")

    # --- Filename Validation ---
    filename = CONFIG_FILE_NAME
    if not filename:
        logging.error("Filename cannot be empty.")
        raise ValueError("Filename cannot be empty")

    if filename.count(".") > 1:
        logging.error("Invalid filename: Multiple '.' characters are not allowed.")
        raise ValueError("Invalid filename: Multiple '.' characters are not allowed.")

    if "/" in filename or "\\" in filename:
        logging.error("Invalid filename: Directory separators are not allowed.")
        raise ValueError("Invalid filename: Directory separators are not allowed.")

    filename = secure_filename(filename)  # Sanitize filename
    if not filename:
        logging.error("Filename is invalid after sanitization.")
        raise ValueError("Invalid filename after sanitization")

    extension = filename.rsplit('.', 1)[1].lower() if '.' in filename else ''
    if extension not in ALLOWED_EXTENSIONS:
        logging.error(f"Invalid file extension: {extension}. Allowed extensions: {ALLOWED_EXTENSIONS}")
        raise ValueError(f"Invalid file extension: {extension}")

    # --- Path Construction ---
    filepath = os.path.join(SAFE_FOLDER, filename)

    # --- Path Traversal Prevention ---
    if not os.path.abspath(filepath).startswith(SAFE_FOLDER):
        logging.error(f"Path traversal detected: {filepath}")
        raise ValueError("Path traversal detected")

    # --- File Creation and Writing ---
    try:
        # Ensure the safe folder exists
        os.makedirs(SAFE_FOLDER, exist_ok=True)

        # Generate a temporary filename to prevent partial writes
        temp_filepath = filepath + ".tmp"

        with open(temp_filepath, "w") as f:
            # Write configuration data (ensure data is already sanitized/encrypted)
            for key, value in config_data.items():
                f.write(f"{key} = {value}\n")

            # Check file size
            if os.path.getsize(temp_filepath) > MAX_FILE_SIZE:
                logging.error(f"File size exceeds maximum allowed size: {MAX_FILE_SIZE} bytes")
                os.remove(temp_filepath)  # Remove the temporary file
                raise ValueError("File size exceeds maximum allowed size")

        # Atomic rename to finalize the file creation
        os.rename(temp_filepath, filepath)

        # --- File Permissions ---
        os.chmod(filepath, stat.S_IRUSR | stat.S_IWUSR)  # Read/Write for owner only

        logging.info(f"Successfully created configuration file: {filepath}")

    except Exception as e:
        logging.exception(f"Error creating configuration file: {e}")
        raise

    finally:
        # Ensure the temporary file is deleted if an error occurred
        if os.path.exists(temp_filepath):
            try:
                os.remove(temp_filepath)
            except Exception as cleanup_err:
                logging.error(f"Failed to clean up temporary file: {cleanup_err}")


def read_secure_config_file():
    """
    Reads the configuration file with security checks.

    Returns:
        dict: A dictionary containing the configuration data, or None if an error occurs.
    """
    filename = CONFIG_FILE_NAME

    if not filename:
        logging.error("Filename cannot be empty.")
        raise ValueError("Filename cannot be empty")

    if filename.count(".") > 1:
        logging.error("Invalid filename: Multiple '.' characters are not allowed.")
        raise ValueError("Invalid filename: Multiple '.' characters are not allowed.")

    if "/" in filename or "\\" in filename:
        logging.error("Invalid filename: Directory separators are not allowed.")
        raise ValueError("Invalid filename: Directory separators are not allowed.")

    filename = secure_filename(filename)  # Sanitize filename
    if not filename:
        logging.error("Filename is invalid after sanitization.")
        raise ValueError("Invalid filename after sanitization")

    extension = filename.rsplit('.', 1)[1].lower() if '.' in filename else ''
    if extension not in ALLOWED_EXTENSIONS:
        logging.error(f"Invalid file extension: {extension}. Allowed extensions: {ALLOWED_EXTENSIONS}")
        raise ValueError(f"Invalid file extension: {extension}")

    filepath = os.path.join(SAFE_FOLDER, filename)

    if not os.path.abspath(filepath).startswith(SAFE_FOLDER):
        logging.error(f"Path traversal detected: {filepath}")
        raise ValueError("Path traversal detected")

    config_data = {}
    try:
        with open(filepath, "r") as f:
            for line in f:
                line = line.strip()
                if line and "=" in line:
                    key, value = line.split("=", 1)
                    config_data[key.strip()] = value.strip()
        logging.info(f"Successfully read configuration file: {filepath}")
        return config_data

    except FileNotFoundError:
        logging.warning(f"Configuration file not found: {filepath}")
        return None
    except Exception as e:
        logging.exception(f"Error reading configuration file: {e}")
        return None


# --- Example Usage ---
if __name__ == "__main__":
    # Simulate sensitive data (in reality, this should be encrypted/hashed)
    sensitive_data = {
        "api_key": secrets.token_hex(32),  # Generate a random API key
        "database_url": "encrypted_db_url",  # Store encrypted data
        "log_level": "INFO"
    }

    try:
        create_secure_config_file(sensitive_data)

        # Read the configuration file
        config = read_secure_config_file()
        if config:
            print("Configuration loaded successfully:")
            print(config)
        else:
            print("Failed to load configuration.")

    except ValueError as e:
        print(f"Error: {e}")

