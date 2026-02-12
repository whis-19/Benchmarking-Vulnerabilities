import logging
import os
import re  # For file path sanitization
from logging.handlers import RotatingFileHandler

# Configure logging (e.g., to a file)
log_formatter = logging.Formatter('%(asctime)s %(levelname)s %(name)s %(message)s')
log_handler = RotatingFileHandler('/var/log/myapp/app.log', maxBytes=1024*1024, backupCount=5) # 1MB file, 5 backups
log_handler.setFormatter(log_formatter)

logger = logging.getLogger(__name__)
logger.addHandler(log_handler)
logger.setLevel(logging.ERROR)

# Set file permissions (after creation) - needs to be done after logging.basicConfig
try:
    os.chmod('/var/log/myapp/app.log', 0o600)  # Restrict permissions
except OSError as e:
    logger.error(f"Failed to set log file permissions: {e}")


class SecureConfigFileError(Exception):
    pass


def create_secure_config_file(file_path: str, file_content: str, allowed_extensions: list[str] = None, allowed_locations: list[str] = None):
    try:
        # --- File Path Sanitization ---
        file_path = os.path.abspath(file_path)  # Canonicalize path
        file_path = os.path.normpath(file_path)  # Remove redundant separators

        # Example: Validate allowed characters in file path (add your own regex)
        if not re.match(r"^[a-zA-Z0-9_\-/.]+$", file_path):
            raise ValueError("Invalid characters in file path.")

        # --- Validation of file_path, file_content, extensions, and locations ---
        if not file_path.endswith(tuple(allowed_extensions)):
            raise ValueError("Invalid file extension.")

        # --- File Content Sanitization (Example - adapt to your file format) ---
        # If file_content is JSON, use json.loads() to validate and sanitize
        # If file_content is YAML, use yaml.safe_load() to validate and sanitize
        # For plain text, escape special characters

        # --- Write the file ---
        with open(file_path, 'w') as f:
            f.write(file_content)

    except ValueError as e:
        logger.error("ValueError during file creation.")
        logger.debug(f"ValueError details: {type(e).__name__}, {e}") # Log type and message in debug mode
        raise SecureConfigFileError("Failed to create secure config file due to invalid input.") from e
    except OSError as e:
        logger.error("OSError during file creation.")
        logger.debug(f"OSError details: {type(e).__name__}, {e}") # Log type and message in debug mode
        raise SecureConfigFileError("Failed to create secure config file due to a system error.") from e
    except Exception as e:  # Catch any other unexpected exceptions
        logger.exception("Unexpected error during file creation.")  # Log the full traceback
        raise SecureConfigFileError("Failed to create secure config file due to an unexpected error.") from e

# Example Usage (Illustrating Error Handling)
try:
    create_secure_config_file("config.txt", "some content", allowed_extensions=[".txt"], allowed_locations=["/tmp"])
except SecureConfigFileError as e:
    print(f"Error creating config file: {e}")

