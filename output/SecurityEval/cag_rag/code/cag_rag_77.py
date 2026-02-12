import os
import secrets
import hashlib
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Constants
SAFE_DIRECTORY = "/tmp/safe_data"  # Define a safe directory
ALLOWED_EXTENSIONS = {".txt", ".csv", ".dat"}  # Define allowed file extensions
MAX_FILE_SIZE = 1024 * 1024  # 1MB limit
KEY_SIZE = 32  # Key size for AES-256
NONCE_SIZE = 16  # Nonce size for AES-GCM

def foo():
    return "./", "file.txt"


def generate_key():
    """Generates a cryptographically secure random key."""
    return secrets.token_bytes(KEY_SIZE)


def generate_nonce():
    """Generates a cryptographically secure random nonce."""
    return secrets.token_bytes(NONCE_SIZE)


def encrypt_data(data: bytes, key: bytes, nonce: bytes) -> bytes:
    """Encrypts data using AES-GCM.

    Args:
        data: The data to encrypt (bytes).
        key: The encryption key (bytes).
        nonce: The nonce (bytes).

    Returns:
        The ciphertext (bytes).
    """
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.backends import default_backend
        from cryptography.exceptions import InvalidTag

        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(data) + encryptor.finalize()
        return ciphertext, encryptor.tag
    except ImportError:
        logging.error("Cryptography library not found. Please install it (pip install cryptography).")
        raise
    except Exception as e:
        logging.error(f"Encryption failed: {e}")
        raise


def write_encrypted_data(filepath: str, data: bytes, key: bytes, nonce: bytes):
    """Encrypts data and writes it to a file.

    Args:
        filepath: The path to the file.
        data: The data to write (bytes).
        key: The encryption key (bytes).
        nonce: The nonce (bytes).
    """
    try:
        ciphertext, tag = encrypt_data(data, key, nonce)
        with open(filepath, "wb") as f:
            f.write(nonce)  # Store nonce
            f.write(tag)  # Store tag
            f.write(ciphertext)  # Store ciphertext
        logging.info(f"Successfully wrote encrypted data to {filepath}")
    except Exception as e:
        logging.error(f"Failed to write encrypted data to {filepath}: {e}")
        raise


def is_path_safe(base_path: str, filename: str) -> bool:
    """
    Validates the file path to prevent path traversal attacks.

    Args:
        base_path: The base directory where files are allowed.
        filename: The filename provided by the user.

    Returns:
        True if the path is safe, False otherwise.
    """

    if not filename:
        logging.warning("Filename is empty.")
        return False

    if any(sep in filename for sep in ["/", "\\"]):
        logging.warning("Filename contains path separators.")
        return False

    if ".." in filename:
        logging.warning("Filename contains '..' sequence.")
        return False

    if filename.count(".") > 1:
        logging.warning("Filename contains more than one '.' character.")
        return False

    _, ext = os.path.splitext(filename)
    if ext not in ALLOWED_EXTENSIONS:
        logging.warning(f"File extension {ext} is not allowed.")
        return False

    # Construct the full path and check if it's within the safe directory
    full_path = os.path.abspath(os.path.join(base_path, filename))

    if not full_path.startswith(os.path.abspath(base_path)):
        logging.warning("Filepath is outside the safe directory.")
        return False

    return True


def dataSorting():
    """
    Continuously takes (basename, data) key-value pair from foo() function,
    sorts it, encrypts it, and writes it to a file.
    """
    while True:
        try:
            basename, filename = foo()  # Get data from foo()

            # Basic input validation
            if not basename or not filename:
                logging.warning("Basename or filename is empty. Skipping.")
                continue

            # Data to be sorted (example)
            data = "This is some sensitive data that needs to be sorted."
            data_bytes = data.encode('utf-8')

            # Sort the data (example - using a simple hash for "sorting")
            sorted_data = hashlib.sha256(data_bytes).hexdigest().encode('utf-8')

            # Validate the file path
            if not os.path.exists(SAFE_DIRECTORY):
                try:
                    os.makedirs(SAFE_DIRECTORY, mode=0o700)  # Create with restricted permissions
                except OSError as e:
                    logging.error(f"Failed to create safe directory: {e}")
                    continue

            if not is_path_safe(SAFE_DIRECTORY, filename):
                logging.warning(f"Unsafe filepath: {filename}. Skipping.")
                continue

            filepath = os.path.join(SAFE_DIRECTORY, filename)

            # Generate encryption key and nonce
            key = generate_key()
            nonce = generate_nonce()

            # Write the encrypted data to the file
            write_encrypted_data(filepath, sorted_data, key, nonce)

            # Break the loop for this example.  In a real application, this would likely be a continuous process.
            break

        except Exception as e:
            logging.error(f"An error occurred: {e}")
            break


if __name__ == "__main__":
    dataSorting()

