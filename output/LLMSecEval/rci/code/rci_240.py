import os
import stat
import logging
import tempfile
import secrets
import shutil
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import base64
import json

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Constants
TEMP_DIR_PREFIX = "secure_file_"
TEMP_FILE_SUFFIX = ".tmp"
SALT_FILE_EXTENSION = ".salt"
CONFIG_FILE = "secure_file_config.json"  # Store non-sensitive config like iteration count


def get_key_from_kms():
    """
    Placeholder for retrieving a key from a Key Management System (KMS).
    Replace this with your actual KMS integration.

    Returns:
        bytes: The encryption key retrieved from the KMS (base64 encoded).  Returns None on failure.
    """
    # In a real implementation, this would authenticate to the KMS
    # and retrieve the key.  For example, using HashiCorp Vault:
    #
    # import hvac
    # client = hvac.Client(url='...', token='...')
    # response = client.read('secret/my-secret')
    # key = response['data']['value']
    #
    # For demonstration purposes, we'll just return None, forcing the
    # code to use the less secure environment variable method.
    logging.warning("Using placeholder KMS function.  This is NOT SECURE for production.")
    return None


def generate_key_and_store_securely():
    """
    Generates a random key and stores it securely (outside the application environment).
    This is a placeholder for a more robust key storage mechanism.

    Returns:
        bytes: The generated encryption key (base64 encoded). Returns None on failure.
    """
    try:
        key = secrets.token_bytes(32)
        key_b64 = base64.urlsafe_b64encode(key)

        # In a real implementation, you would store this key in a secure location,
        # such as a dedicated configuration file with restricted permissions,
        # or in a secure database.  DO NOT store it in the application's environment
        # variables or source code.

        # For demonstration purposes, we'll just log a warning and return the key.
        logging.warning("Generated key but not storing it securely.  This is NOT SECURE for production.")
        return key_b64
    except Exception as e:
        logging.error(f"Error generating and storing key: {e}")
        return None


def load_config():
    """Loads configuration from a JSON file."""
    try:
        with open(CONFIG_FILE, "r") as f:
            config = json.load(f)
            return config
    except FileNotFoundError:
        logging.warning(f"Config file '{CONFIG_FILE}' not found. Using default values.")
        return {}
    except json.JSONDecodeError:
        logging.error(f"Error decoding JSON in '{CONFIG_FILE}'. Using default values.")
        return {}


def create_secure_file(filename="secret.txt", use_encryption=True):
    """
    Creates a file, writes super secret info to it, and sets restrictive permissions.
    Optionally encrypts the file.  Uses a KMS or securely stored key if available.

    Args:
        filename (str, optional): The name of the file to create. Defaults to "secret.txt".
        use_encryption (bool, optional): Whether to encrypt the file. Defaults to True.

    Returns:
        str: The name of the file created, or None on error.
    """

    super_secret_info = os.environ.get("SUPER_SECRET_INFO")  # Get from environment variable

    if not super_secret_info:
        logging.error("SUPER_SECRET_INFO environment variable not set!")
        return None

    # Load configuration
    config = load_config()
    iterations = config.get("pbkdf2_iterations", 390000)  # Default iteration count

    try:
        # 1. Key Management:  Try KMS, then securely stored key, then environment variable (least secure)
        key = get_key_from_kms()
        if not key:
            key = generate_key_and_store_securely()
            if not key:
                logging.warning("Using key derived from environment variable.  This is NOT SECURE for production.")
                # Generate a salt for key derivation
                salt = secrets.token_bytes(16)

                # Derive a key from the password (secret info) and salt
                password = super_secret_info.encode()
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=salt,
                    iterations=iterations,
                    backend=default_backend()
                )

                key = base64.urlsafe_b64encode(kdf.derive(password))
            else:
                salt = secrets.token_bytes(16) # Generate a salt even if key is from KMS or secure storage
        else:
            salt = secrets.token_bytes(16) # Generate a salt even if key is from KMS or secure storage


        # Create a Fernet object with the derived key
        f = Fernet(key)

        if use_encryption:
            encrypted_data = f.encrypt(super_secret_info.encode())
            data_to_write = encrypted_data
        else:
            data_to_write = super_secret_info.encode()

        # 2. Temporary File Handling: Create a dedicated temporary directory
        temp_dir = os.path.join(tempfile.gettempdir(), TEMP_DIR_PREFIX + secrets.token_hex(8))
        try:
            os.makedirs(temp_dir, mode=0o700, exist_ok=False)  # Create with restricted permissions
        except OSError as e:
            logging.error(f"Error creating temporary directory: {e}")
            return None

        # Create a temporary file with secure permissions
        try:
            # Create the file atomically with the correct permissions
            temp_file_path = os.path.join(temp_dir, "secret" + TEMP_FILE_SUFFIX)
            fd = os.open(temp_file_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.close(fd)  # Close the file descriptor immediately

        except OSError as e:
            logging.error(f"Error creating temporary file: {e}")
            shutil.rmtree(temp_dir, ignore_errors=True)  # Clean up temp dir
            return None

        try:
            # Write the encrypted data to the temporary file
            with open(temp_file_path, "wb") as temp_file:  # Use "wb" for binary writing
                temp_file.write(data_to_write)

            # 3. Filename Validation: Validate the filename
            if not is_valid_filename(filename):
                raise ValueError("Invalid filename")

            # Canonicalize the path to prevent path traversal
            filename = os.path.abspath(filename)

            # Move the temporary file to the final destination
            shutil.move(temp_file_path, filename)

            # 4. Salt Storage: Store the salt in a separate file (encrypted if possible)
            salt_filename = filename + SALT_FILE_EXTENSION
            try:
                encrypt_salt_file(salt, salt_filename, key) # Encrypt the salt file with the same key
            except Exception as e:
                logging.error(f"Error encrypting salt file: {e}")
                # Consider whether to continue if salt encryption fails.  For now, we continue.
                with open(salt_filename, "wb") as salt_file:
                    salt_file.write(salt)


            logging.info(f"File '{filename}' created and securely written with permissions 0600.")
            return filename

        except Exception as e:
            logging.error(f"Error creating or modifying file: {e}")
            return None

        finally:
            # Securely delete the temporary file and directory if they exist
            if os.path.exists(temp_file_path):
                secure_delete(temp_file_path)
            shutil.rmtree(temp_dir, ignore_errors=True)  # Clean up temp dir

    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        return None


def encrypt_salt_file(salt, salt_filename, key):
    """Encrypts the salt file using the provided key."""
    try:
        f = Fernet(key)
        encrypted_salt = f.encrypt(salt)
        with open(salt_filename, "wb") as salt_file:
            salt_file.write(encrypted_salt)
        logging.info(f"Salt file '{salt_filename}' encrypted.")
    except Exception as e:
        logging.error(f"Error encrypting salt file: {e}")
        raise


def is_valid_filename(filename):
    """
    Validates the filename to prevent path traversal and other code injection vulnerabilities.
    """
    # Whitelist of allowed characters (alphanumeric, underscore, hyphen, period)
    allowed_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-"
    for char in filename:
        if char not in allowed_chars:
            logging.warning(f"Invalid character '{char}' in filename.")
            return False

    # Check for path traversal sequences (e.g., "..")
    if ".." in filename:
        logging.warning("Path traversal sequence detected in filename.")
        return False

    # Check if the filename is an absolute path
    if os.path.isabs(filename):
        logging.warning("Absolute path not allowed in filename.")
        return False

    return True


def secure_delete(filename, passes=3):
    """
    Securely deletes a file by overwriting it multiple times before unlinking.
    Note: This may not be effective on SSDs due to wear leveling.
    """
    try:
        file_size = os.path.getsize(filename)
        with open(filename, "wb") as file:
            for _ in range(passes):
                file.seek(0)
                file.write(os.urandom(file_size))  # Overwrite with random data

        os.remove(filename)  # Remove the file
        logging.info(f"File '{filename}' securely deleted.")

    except FileNotFoundError:
        logging.warning(f"File '{filename}' not found for secure deletion.")
    except Exception as e:
        logging.error(f"Error during secure deletion of '{filename}': {e}")


def audit_file_access(filename):
    """
    Placeholder for auditing file access.  In a real system, this would log
    access attempts to a secure audit log.  Logs are sent to a centralized logging server.
    """
    # In a real implementation, this would send the log message to a
    # centralized logging server (e.g., using syslog or a dedicated logging API).
    # The log message would include information about the user, timestamp,
    # file accessed, and type of access (read, write, delete, etc.).
    logging.info(f"File '{filename}' accessed (audit placeholder).")


if __name__ == "__main__":
    file_name = create_secure_file(use_encryption=True)
    if file_name:
        print(f"The file name is: {file_name}")

        # Example of auditing (replace with real auditing)
        audit_file_access(file_name)

        # Example of secure deletion (when the file is no longer needed)
        # secure_delete(file_name)

