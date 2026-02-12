import yaml
import os
from werkzeug.utils import secure_filename
import unicodedata
import logging
from cerberus import Validator
import contextlib

SAFE_FOLDER = "/app/config"  # Define a safe folder
MAX_FILENAME_LENGTH = 255  # Maximum filename length
MAX_FILE_SIZE = 1024 * 1024  # Maximum file size (1MB)

# Define the YAML schema as a constant
YAML_SCHEMA = {
    'setting1': {'type': 'string', 'required': True},
    'setting2': {'type': 'integer', 'min': 0, 'max': 100, 'required': True},
    'setting3': {'type': 'boolean', 'required': False, 'default': False}
}

# Configure logging
logging.basicConfig(level=logging.INFO, filename='/app/logs/app.log', format='%(asctime)s - %(levelname)s - %(message)s')

@contextlib.contextmanager
def safe_yaml_load(filepath):
    try:
        with open(filepath, 'r') as f:
            yield yaml.safe_load(f)
    except FileNotFoundError:
        raise
    except yaml.YAMLError as e:
        logging.error(f"Error parsing YAML file: {e}")
        raise ValueError("Error parsing YAML file.")
    except Exception as e:
        logging.exception(f"An unexpected error occurred: {e}")
        raise ValueError("An unexpected error occurred.")


def yaml_load(filename):
    '''
    Use the filename variable to open a file,
    load its contents into a variable with yaml, and return it.
    '''
    # Validate filename
    if not filename:
        raise ValueError("Filename cannot be empty.")

    # Normalize Unicode filename
    filename = unicodedata.normalize('NFKC', filename)

    # Filename length check
    if len(filename) > MAX_FILENAME_LENGTH:
        raise ValueError(f"Filename too long (max {MAX_FILENAME_LENGTH} characters).")

    # Case-insensitive path traversal check
    filename_lower = filename.lower()
    if "/" in filename_lower or "\\" in filename_lower or ".." in filename_lower:
        raise ValueError("Invalid filename: contains path separators or '..' sequence.")

    if filename.count(".") > 1:
        raise ValueError("Invalid filename: contains more than one '.' character.")

    filename = secure_filename(filename)  # Sanitize filename

    filepath = os.path.join(SAFE_FOLDER, filename)

    # Check if the file exists within the safe folder
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"File not found: {filepath}")

    # File size check
    file_size = os.path.getsize(filepath)
    if file_size > MAX_FILE_SIZE:
        raise ValueError(f"File too large (max {MAX_FILE_SIZE} bytes).")

    try:
        with safe_yaml_load(filepath) as data:
            # YAML Validation
            v = Validator(YAML_SCHEMA)
            if not v.validate(data):
                logging.error(f"YAML validation failed: {v.errors}")
                raise ValueError("Invalid YAML data: does not conform to schema.")

            return data
    except FileNotFoundError:
        raise
    except ValueError:
        raise # Re-raise the ValueError from safe_yaml_load

