import os
import json
import hmac
import hashlib
from urllib.parse import quote, unquote
import html  # Import the html module
import secrets
import logging  # Import the logging module

# --- Security Configuration ---
ALLOWED_FILE_EXTENSIONS = ['.json']  # Only allow JSON files
DATA_DIRECTORY = 'safe_data'  # Store data in a dedicated directory
# HMAC_SECRET = b'Your_Secret_Key_Here'  # Replace with a strong, randomly generated secret key.  Store securely!
HMAC_SECRET = os.environ.get('HMAC_SECRET')
if not HMAC_SECRET:
    raise ValueError("HMAC_SECRET environment variable not set!")
HMAC_SECRET = HMAC_SECRET.encode('utf-8')  # Encode to bytes

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

MAX_JSON_SIZE = 1024 * 1024  # 1 MB limit


def sanitize_filename(filename):
    """Sanitizes a filename to prevent path traversal."""
    if not isinstance(filename, str):
        raise ValueError("Filename must be a string.")

    filename = os.path.basename(filename)  # Extract filename from path

    # Whitelist approach:  Allow only alphanumeric, underscore, and hyphen
    allowed_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"
    sanitized_filename = ''.join(c for c in filename if c in allowed_chars or c == '.')

    # Add a length limit
    max_filename_length = 255  # Or a suitable value
    if len(sanitized_filename) > max_filename_length:
        sanitized_filename = sanitized_filename[:max_filename_length]

    return sanitized_filename


def secure_load_data(file_path):
    """
    Securely loads data from a JSON file, verifying integrity and sanitizing the file path.
    """
    max_retries = 3  # For TOCTOU mitigation
    for attempt in range(max_retries):
        try:
            # 1. Validate and Sanitize File Path
            if not isinstance(file_path, str):
                raise ValueError("File path must be a string.")

            # **IMPORTANT: If file_path comes from a URL, UNQUOTE IT HERE!**
            # file_path = unquote(file_path)

            file_path = sanitize_filename(file_path)

            # 2. Prevent Path Traversal
            if ".." in file_path:
                raise ValueError("Invalid file path: Path traversal detected.")

            # 3. Use an Allowlist for File Extensions
            if not is_allowed_file_extension(file_path, ALLOWED_FILE_EXTENSIONS):
                raise ValueError("Invalid file extension. Only JSON files are allowed.")

            # 4. Construct the full, safe file path
            full_file_path = os.path.join(DATA_DIRECTORY, file_path)
            full_file_path = os.path.abspath(full_file_path)  # Canonicalize the path

            # Ensure the file is within the allowed directory
            if not full_file_path.startswith(os.path.abspath(DATA_DIRECTORY) + os.sep):
                raise ValueError("Path traversal detected.")


            # 5. Check if the file exists
            if not os.path.exists(full_file_path):
                logging.warning(f"File not found: {full_file_path}") # Log the warning
                return None  # Or raise a FileNotFoundError

            # 6. Read the file content
            try:
                with open(full_file_path, 'r') as f:
                    content = f.read()
            except OSError as e:
                logging.error(f"Error reading file {full_file_path}: {e}")
                if attempt < max_retries - 1:
                    logging.info(f"Retrying file read (attempt {attempt + 1})")
                    continue  # Retry
                else:
                    return None # Or raise the exception

            if len(content) > MAX_JSON_SIZE:
                logging.error("Error: JSON data exceeds maximum size limit.")
                return None

            # 7. Split the content into data and HMAC
            try:
                data, hmac_value = content.rsplit('||', 1)  # Use a clear separator
            except ValueError:
                logging.error(f"File {full_file_path} does not contain HMAC.  Data may be corrupted.")
                return None

            # 8. Verify the HMAC
            if not verify_hmac(data, hmac_value, HMAC_SECRET):
                logging.error(f"HMAC verification failed for {full_file_path}. Data may be tampered with.")
                return None

            # 9. Validate data before deserialization
            is_valid, error_message = validate_data_before_deserialization(data)
            if not is_valid:
                logging.error(f"Data validation failed for {full_file_path}: {error_message}")
                return None

            # 10. Deserialize the data using json.loads (safe deserialization)
            try:
                deserialized_data = json.loads(data)
                return deserialized_data
            except json.JSONDecodeError as e:
                logging.error(f"Error decoding JSON from {full_file_path}: {e}")
                return None
            break # If successful, break the retry loop

        except (ValueError, OSError, FileNotFoundError) as e:  # Specific exceptions
            logging.error(f"Error loading data from {file_path}: {e}")
            return None
        except Exception as e:
            logging.exception(f"An unexpected error occurred while processing {file_path}: {e}") # Log the full exception
            return None
    else:
        logging.error(f"Failed to load data from {file_path} after {max_retries} attempts.")
        return None

# Example functions (replace with your actual implementations)
def is_allowed_file_extension(filename, allowed_extensions):
    """Checks if the file extension is in the allowed list."""
    _, ext = os.path.splitext(filename)
    return ext.lower() in allowed_extensions

def verify_hmac(data, hmac_value, secret):
    """Verifies the HMAC of the data."""
    calculated_hmac = hmac.new(secret, data.encode('utf-8'), hashlib.sha256).hexdigest()
    return hmac.compare_digest(calculated_hmac, hmac_value)

def validate_data_before_deserialization(data):
    """Validates the data before deserialization.  **IMPLEMENT THIS!**"""
    # Example: Check for required fields, data types, and value ranges
    try:
        json_data = json.loads(data)  # Parse JSON to check structure
        if not isinstance(json_data, dict):
            return False, "Data must be a JSON object (dictionary)."
        # Add more validation rules here based on your data structure
        return True, None  # Data is valid
    except json.JSONDecodeError:
        return False, "Invalid JSON format."

