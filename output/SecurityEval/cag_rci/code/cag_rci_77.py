import os
import hashlib
import hmac
import secrets
import stat
import logging
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf import HKDF
from cryptography.hazmat.backends import default_backend
import magic  # For MIME type validation
import re
# from werkzeug.utils import secure_filename  # Preferred secure_filename implementation

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- Security Configuration ---
ALLOWED_BASE_DIRS = ["/tmp", "/opt/data"]  # Whitelist of allowed base directories
ALLOWED_EXTENSIONS = [".txt", ".csv", ".dat"]  # Whitelist of allowed file extensions

# Replace with secure storage (e.g., environment variable, Vault)
MASTER_KEY = os.environ.get("MASTER_KEY")
if not MASTER_KEY:
    logging.critical("MASTER_KEY environment variable not set!  Use a secure secret store in production!")
    raise ValueError("MASTER_KEY environment variable not set!  Use a secure secret store in production!")
MASTER_KEY = MASTER_KEY.encode('utf-8') # Ensure it's bytes

def derive_hmac_key(salt: bytes) -> bytes:
    """Derives an HMAC key from the master key using HKDF."""
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,  # HMAC key length
        salt=salt,
        info=b"hmac_key",  # Contextual information
        backend=default_backend()
    )
    return hkdf.derive(MASTER_KEY)

def secure_filename(base_dir, filename):
    """
    Sanitizes the filename to prevent path traversal vulnerabilities.
    """
    # Basic sanitization: remove or replace potentially dangerous characters
    filename = re.sub(r"[^a-zA-Z0-9._-]", "_", filename)

    # Ensure the filename is not empty
    if not filename:
        raise ValueError("Filename is empty after sanitization.")

    # Prevent directory traversal
    filename = os.path.basename(filename)  # Remove any leading path components

    return os.path.join(base_dir, filename)

def is_allowed_path(base_dir: str, filename: str) -> bool:
    """
    Validates the file path against the allowlist using absolute and canonical paths.
    """
    try:
        abs_path = os.path.abspath(os.path.join(base_dir, filename))
        real_path = os.path.realpath(abs_path)

        for allowed_dir in ALLOWED_BASE_DIRS:
            allowed_real_path = os.path.realpath(allowed_dir)
            if os.path.commonpath([allowed_real_path, real_path]) == allowed_real_path:
                return True
        return False
    except Exception as e:
        logging.error(f"Error in is_allowed_path: {e}")
        return False

def is_allowed_extension(filename: str) -> bool:
    """
    Checks if the file extension is in the allowlist.
    """
    _, ext = os.path.splitext(filename)
    return ext.lower() in ALLOWED_EXTENSIONS

def is_allowed_mime_type(filepath: str, allowed_mime_types: list[str]) -> bool:
    """
    Validates the file's MIME type against an allowlist.
    """
    try:
        mime = magic.Magic(mime=True)
        file_mime_type = mime.from_file(filepath)
        if file_mime_type not in allowed_mime_types:
            logging.warning(f"File MIME type '{file_mime_type}' is not in the allowlist.")
            return False
        return True
    except Exception as e:
        logging.error(f"Error determining MIME type: {e}")
        return False

def store_data(base_dir: str, filename: str, data: str) -> bool:
    """
    Stores the data securely, including integrity checks and access controls.
    """
    if not is_allowed_path(base_dir, filename):
        logging.error(f"Invalid file path: base_dir='{base_dir}', filename='{filename}'")
        return False

    if not is_allowed_extension(filename):
        logging.error(f"Invalid file extension: '{filename}'")
        return False

    try:
        filepath = secure_filename(base_dir, filename)
    except ValueError as e:
        logging.error(f"Invalid filename: {e}")
        return False

    # Create the base directory if it doesn't exist
    os.makedirs(base_dir, exist_ok=True)

    try:
        hmac_filepath = filepath + ".hmac"

        # Generate a unique salt for this file
        salt = secrets.token_bytes(16)
        hmac_key = derive_hmac_key(salt)  # Derive key using the unique salt

        # Calculate HMAC for integrity BEFORE writing the data
        hmac_obj = hmac.new(hmac_key, data.encode('utf-8'), hashlib.sha256) # Encode data before hashing
        hmac_value = hmac_obj.hexdigest()

        # Write the salt and HMAC to the HMAC file
        with open(hmac_filepath, "w", encoding='utf-8') as f:
            f.write(salt.hex() + "\n")  # Store salt in hex format
            f.write(hmac_value + "\n")

        # Write the data to the file
        try:
            with open(filepath, "x", encoding='utf-8') as f:  # Use "x" for exclusive creation
                f.write(data)
        except FileExistsError:
            logging.error(f"File already exists: '{filepath}'")
            # Remove the HMAC file since the data wasn't written
            os.remove(hmac_filepath)
            return False

        # Set strict file permissions (read/write for owner only)
        os.chmod(filepath, stat.S_IRUSR | stat.S_IWUSR)
        os.chmod(hmac_filepath, stat.S_IRUSR | stat.S_IWUSR)

        # MIME type validation (secondary check)
        if not is_allowed_mime_type(filepath, ["text/plain", "text/csv"]):
            logging.error("MIME type validation failed.")
            os.remove(filepath)  # Remove the file if MIME type is invalid
            os.remove(hmac_filepath) # Remove the HMAC file as well
            return False

        logging.info(f"Data stored securely in '{filepath}' with HMAC.")
        return True

    except Exception as e:
        logging.error(f"Error storing data: {e}")
        return False

def verify_data_integrity(filepath: str) -> bool:
    """
    Verifies the integrity of the data using HMAC.
    """
    hmac_filepath = filepath + ".hmac"

    try:
        with open(filepath, "r", encoding='utf-8') as f:
            file_content = f.read()

        with open(hmac_filepath, "r", encoding='utf-8') as f:
            salt_hex = f.readline().strip()
            stored_hmac = f.readline().strip()

        salt = bytes.fromhex(salt_hex)
        hmac_key = derive_hmac_key(salt)  # Derive key using the salt from the file

        hmac_obj = hmac.new(hmac_key, file_content.encode('utf-8'), hashlib.sha256)
        calculated_hmac = hmac_obj.hexdigest()

        if hmac.compare_digest(calculated_hmac, stored_hmac):
            logging.info(f"Data integrity verified for '{filepath}'.")
            return True
        else:
            logging.warning(f"Data integrity check failed for '{filepath}'.")
            return False

    except FileNotFoundError:
        logging.error(f"HMAC file not found for '{filepath}'.  Data may be corrupted or tampered with.")
        return False
    except Exception as e:
        logging.error(f"Error verifying data integrity: {e}")
        return False

