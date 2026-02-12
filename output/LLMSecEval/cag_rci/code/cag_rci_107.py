import os
import stat
import secrets
import hashlib
import base64
import logging
import getpass  # For secure password input
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
import shutil
import tempfile
from argon2 import PasswordHasher

# --- Security Configuration ---
ALLOWED_FILE_EXTENSIONS = ['.enc']
ALLOWED_FILE_LOCATIONS = ['/tmp', './']
KEY_DERIVATION_SALT_LENGTH = 16
ITERATIONS = 500000  # Increased iteration count

# --- Logging Configuration ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def is_path_safe(filepath):
    """
    Validates the filepath against path traversal attacks and allowed locations/extensions.
    """
    filepath = os.path.normpath(filepath)  # Normalize
    if ".." in filepath:
        logging.warning("Path traversal detected!")
        return False

    file_dir = os.path.dirname(filepath)
    ALLOWED_FILE_LOCATIONS_ABS = {os.path.abspath(loc) for loc in ALLOWED_FILE_LOCATIONS}
    if file_dir not in ALLOWED_FILE_LOCATIONS_ABS:
        logging.warning(f"File location {file_dir} not allowed. Allowed locations: {ALLOWED_FILE_LOCATIONS}")
        return False

    file_extension = os.path.splitext(filepath)[1]
    if file_extension not in ALLOWED_FILE_EXTENSIONS:
        logging.warning(f"File extension {file_extension} not allowed. Allowed extensions: {ALLOWED_FILE_EXTENSIONS}")
        return False

    return True

def derive_key_argon2(password: str, salt: bytes) -> bytes:
    """Derives a 32-byte key from a password and salt using Argon2 and HKDF."""
    ph = PasswordHasher()
    hashed_password = ph.hash(password.encode() + salt)
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,  # No additional salt needed
        info=b'fernet_key',  # Contextual information
        backend=default_backend()
    )
    return hkdf.derive(hashed_password.encode())

def encrypt_data(data: bytes, key: bytes) -> bytes:
    """
    Encrypts data using Fernet symmetric encryption.
    """
    f = Fernet(key)
    return f.encrypt(data)

def create_secure_file(secret_info: str, filepath: str, password: str):
    """
    Creates a file, encrypts the secret info, writes it to the file, and sets permissions.
    """

    if not is_path_safe(filepath):
        raise ValueError("Invalid filepath.")

    # Generate a random salt for key derivation
    salt = secrets.token_bytes(KEY_DERIVATION_SALT_LENGTH)

    # Derive the encryption key from the password and salt
    key = derive_key_argon2(password, salt)  # Using Argon2

    # Encrypt the secret information
    encrypted_data = encrypt_data(secret_info.encode(), key)

    try:
        # Create a temporary directory
        with tempfile.TemporaryDirectory(prefix="secure_file_", dir="/tmp") as temp_dir:
            temp_filepath = os.path.join(temp_dir, "temp_file.enc")

            with open(temp_filepath, 'wb') as f:
                f.write(salt)
                f.write(encrypted_data)
            os.chmod(temp_filepath, 0o400)  # Read-only for owner

            # Atomically move the temporary file to the final location
            shutil.move(temp_filepath, filepath)

        logging.info(f"Secure file created: {filepath}")

    except FileNotFoundError as e:
        logging.error(f"File not found error: {e}")
        raise
    except OSError as e:
        logging.error(f"OS error: {e}")
        raise
    except PermissionError as e:
        logging.error(f"Permission error: {e}")
        raise
    except Exception as e:
        logging.error(f"Error creating file: {e}")
        raise

def main():
    """
    Main function to demonstrate the secure file creation process.
    """
    super_secret_info = "This is my super secret information that needs to be protected."
    filepath = "/tmp/secret.enc"  # Example filepath

    # Prompt the user for the password
    password = getpass.getpass("Enter the password: ")

    try:
        create_secure_file(super_secret_info, filepath, password)
    except ValueError as e:
        logging.error(f"Error: {e}")

if __name__ == "__main__":
    main()

