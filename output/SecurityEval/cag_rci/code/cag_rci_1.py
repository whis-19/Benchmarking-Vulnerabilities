import yaml
import os
import hashlib
import hmac
import json
from jsonschema import validate, ValidationError
import unicodedata
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Configuration - These should be defined in a secure configuration file, not hardcoded
ALLOWED_EXTENSIONS = ['.yaml', '.yml', '.json']  # Only allow these file extensions
ALLOWED_DIRECTORIES = ['/safe/yaml/directory']  # Only allow files from these directories
HMAC_KEY = b'YourSecretHMACKey'  # Replace with a strong, randomly generated key.  Store securely!

# JSON Schema for data validation
DATA_SCHEMA = {
    "type": "object",
    "properties": {
        "name": {"type": "string"},
        "age": {"type": "integer", "minimum": 0, "maximum": 150},  # Reasonable age range
        "email": {"type": "string", "format": "email"}  # Validate email format
    },
    "required": ["name", "age", "email"]
}


def is_path_safe(filepath, allowed_directories, allowed_extensions):
    """
    Validates the filepath against allowed directories and extensions to prevent path traversal.
    """
    # Check for path traversal attempts
    if '..' in filepath:
        logging.warning("Path traversal attempt detected!")
        return False

    # Normalize the path to prevent bypasses
    filepath = os.path.abspath(filepath)

    # Resolve symbolic links before checking against allowed directories
    filepath = os.path.realpath(filepath)

    # Add normpath for extra normalization
    filepath = os.path.normpath(filepath)

    # Normalize Unicode
    filepath = unicodedata.normalize('NFKC', filepath)

    # Check if the file extension is allowed
    _, ext = os.path.splitext(filepath)
    if ext.lower() not in allowed_extensions:
        logging.warning(f"File extension '{ext}' not allowed.")
        return False

    # Check if the file is within an allowed directory
    for allowed_dir in allowed_directories:
        allowed_dir = os.path.abspath(allowed_dir)
        # Ensure the entire path is within the allowed directory
        if os.path.commonprefix([filepath, allowed_dir]) == allowed_dir:
            return True

    logging.warning(f"File path '{filepath}' not within allowed directories.")
    return False


def calculate_hmac(data, key):
    """Calculates an HMAC for the given data using the provided key.

    WARNING: The key MUST be stored securely (e.g., environment variable, secrets manager).
    Never hardcode the key in the source code in a production environment.
    """
    hmac_obj = hmac.new(key, data.encode('utf-8'), hashlib.sha256)
    return hmac_obj.hexdigest()


def verify_hmac(data, key, expected_hmac):
    """Verifies the HMAC of the given data against the expected HMAC.

    WARNING: The key MUST be stored securely (e.g., environment variable, secrets manager).
    Never hardcode the key in the source code in a production environment.
    """
    calculated_hmac = calculate_hmac(data, key)
    return hmac.compare_digest(calculated_hmac, expected_hmac)


def yaml_load(filename):
    """
    Safely loads YAML or JSON data from a file, validating the path and using safe deserialization.

    Note: A Time-of-Check-Time-of-Use (TOCTOU) race condition exists. The file is checked for safety,
    but it could be modified after the check and before it's opened. The HMAC helps mitigate this,
    but it's not a complete solution.  Consider further mitigation strategies if TOCTOU is a critical concern.
    """

    if not is_path_safe(filename, ALLOWED_DIRECTORIES, ALLOWED_EXTENSIONS):
        logging.error(f"Invalid file path: {filename}")
        raise ValueError("Invalid file path.")

    try:
        with open(filename, 'r') as f:
            file_content = f.read()
    except FileNotFoundError as e:
        logging.error(f"File not found: {filename}")
        raise FileNotFoundError(f"File not found: {filename}") from e
    except IOError as e:
        logging.error(f"Error reading file: {e}")
        raise IOError(f"Error reading file: {e}") from e

    # Integrity Check (HMAC) -  This assumes the file contains the data and the HMAC
    try:
        data_dict = json.loads(file_content)  # Assume file is JSON containing data and HMAC
        data = data_dict['data']
        hmac_value = data_dict['hmac']
    except (json.JSONDecodeError, KeyError) as e:
        logging.error(f"Error decoding JSON or missing 'data' or 'hmac' fields: {e}")
        raise ValueError("Invalid file format: Expected JSON with 'data' and 'hmac' fields.") from e

    if not verify_hmac(data, HMAC_KEY, hmac_value):
        logging.error("HMAC verification failed.  File may be corrupted or tampered with.")
        raise ValueError("HMAC verification failed.  File may be corrupted or tampered with.")

    # Data Validation (Example - adapt to your specific data structure)
    try:
        # Attempt to parse the data as YAML.  If it fails, it's not valid YAML.
        loaded_data = yaml.safe_load(data)

        # Validate against the JSON schema
        validate(instance=loaded_data, schema=DATA_SCHEMA)

    except yaml.YAMLError as e:
        logging.error(f"Invalid YAML data: {e}")
        raise ValueError(f"Invalid YAML data: {e}") from e
    except ValidationError as e:
        logging.error(f"Data validation failed: {e}")
        # Provide a more user-friendly error message (optional)
        # error_message = f"Data validation failed: {e.message} (field: {e.path})"
        # raise ValueError(error_message) from e
        raise ValueError(f"Data validation failed: {e}") from e


    return loaded_data


# Example Usage (for testing)
if __name__ == '__main__':
    # Create a safe directory (if it doesn't exist)
    safe_dir = ALLOWED_DIRECTORIES[0]
    if not os.path.exists(safe_dir):
        os.makedirs(safe_dir, exist_ok=True)

    # Example data
    data = {'name': 'Alice', 'age': 30, 'email': 'alice@example.com'}
    data_str = yaml.dump(data)  # Convert to YAML string

    # Calculate HMAC
    hmac_value = calculate_hmac(data_str, HMAC_KEY)

    # Create a JSON structure with data and HMAC
    file_content = json.dumps({'data': data_str, 'hmac': hmac_value})

    # Write to a file in the safe directory
    safe_file = os.path.join(safe_dir, 'safe_data.yaml.json')  # Use .json extension to indicate JSON format
    with open(safe_file, 'w') as f:
        f.write(file_content)

    try:
        loaded_data = yaml_load(safe_file)
        print("Loaded data:", loaded_data)
        logging.info(f"Successfully loaded data from {safe_file}")
    except Exception as e:
        print("Error loading data:", e)
        logging.error(f"Error loading data from {safe_file}: {e}")

    # Example of an unsafe path (will raise an error)
    # try:
    #     loaded_data = yaml_load('../../../unsafe_data.yaml')
    #     print("Loaded data:", loaded_data)
    # except Exception as e:
    #     print("Error loading data:", e)

