import yaml
import os
import logging
import logging.config
from pathlib import Path

# Attempt to load logging configuration from file, fallback to basic config
try:
    logging.config.fileConfig('logging.conf')  # Create a logging.conf file
    logger = logging.getLogger()  # Get the root logger
    logger.info("Logging configuration loaded from file.")
except FileNotFoundError:
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    logger = logging.getLogger()
    logger.warning("Logging configuration file not found. Using basic configuration.")
except Exception as e:
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    logger = logging.getLogger()
    logger.error(f"Error loading logging configuration: {e}. Using basic configuration.")


def yaml_load(filename):
    '''
    Use the filename variable to open a file,
    load its contents into a variable with yaml, and return it.
    '''
    # Validate filename - crucial for security
    if not isinstance(filename, str):
        logger.error("Filename must be a string.")
        raise TypeError("Filename must be a string.")

    # Use pathlib for path manipulation
    filepath = Path(filename).resolve()  # Normalizes and makes absolute

    # Check if the path is absolute (disallowed)
    if filepath.is_absolute():
        logger.error("Filename must be a relative path.")
        raise ValueError("Filename must be a relative path.")

    # Check for directory separators AFTER normalization (using pathlib)
    if ".." in str(filepath):  # Convert Path object to string for simpler check
        logger.error("Filename cannot contain '..' for security reasons.")
        raise ValueError("Filename cannot contain '..' for security reasons.")

    # Whitelist allowed file extensions
    allowed_extensions = ['.yaml', '.yml']
    if filepath.suffix.lower() not in allowed_extensions:
        logger.error(f"Invalid file extension. Allowed extensions: {allowed_extensions}")
        raise ValueError(f"Invalid file extension. Allowed extensions: {allowed_extensions}")

    # Optional: Restrict allowed characters in filename (using pathlib)
    # allowed_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"
    # if not all(c in allowed_chars for c in filepath.name):
    #     logger.error("Filename contains invalid characters.")
    #     raise ValueError("Filename contains invalid characters.")

    try:
        with filepath.open('r') as f:
            data = yaml.safe_load(f)  # Use safe_load for security
            logger.info(f"Successfully loaded YAML from {filepath}")
            return data
    except FileNotFoundError:
        logger.error(f"File not found: {filepath}")
        print(f"Error: File not found: {filepath}")  # Keep print for user feedback
        return None
    except yaml.YAMLError as e:
        logger.error(f"Error parsing YAML: {e}")
        print(f"Error parsing YAML: {e}")  # Keep print for user feedback
        return None
    except Exception as e:
        logger.exception(f"An unexpected error occurred: {e}")  # Log the full exception
        print(f"An unexpected error occurred: {e}")  # Keep print for user feedback
        return None

