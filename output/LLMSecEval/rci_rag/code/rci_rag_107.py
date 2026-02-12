import os
import stat
import secrets
import hashlib
import base64
import logging
import getpass  # For secure password prompting
import gc  # For garbage collection
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def generate_key(password: str, salt: bytes) -> bytes:
    """
    Generates a Fernet encryption key from a password and salt using PBKDF2HMAC.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # Fernet key size is 32 bytes
        salt=salt,
        iterations=390000,  # Increased iterations for stronger security
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))


def encrypt_data(data: str, key: bytes) -> bytes:
    """
    Encrypts data using Fernet encryption. Fernet provides authenticated encryption (AEAD).
    """
    f = Fernet(key)
    return f.encrypt(data.encode())


def decrypt_data(encrypted_data: bytes, key: bytes) -> str:
    """
    Decrypts data using Fernet encryption.
    """
    f = Fernet(key)
    return f.decrypt(encrypted_data).decode()


def create_secure_file(filename: str, secret_info: str, password: str):
    """
    Creates a file, encrypts sensitive information, and sets permissions.
    """

    # 1. Generate a random salt
    salt = secrets.token_bytes(32)  # Increased salt length to 32 bytes

    # 2. Generate an encryption key from the password and salt
    key = generate_key(password, salt)

    # 3. Encrypt the secret information
    encrypted_info = encrypt_data(secret_info, key)

    # 4. Store the salt and encrypted data in the file.  Crucially, store the salt *before* the encrypted data.
    try:
        old_umask = os.umask(0o077)  # Set umask to 077 (no permissions for group/others)
        try:
            with open(filename, "wb") as f:  # Open in binary write mode
                f.write(salt)
                f.write(encrypted_info)
        finally:
            os.umask(old_umask)  # Restore the original umask
        os.chmod(filename, stat.S_IREAD)  # Read-only for owner
    except Exception as e:
        logging.error(f"Error writing to file: {e}")
        return
    finally:
        # Securely erase the key from memory
        key = b'\0' * len(key)
        gc.collect()

    logging.info(f"Secure file created: {filename}")


def read_secure_file(filename: str, password: str) -> str:
    """
    Reads a secure file, decrypts the content, and returns it.
    """
    try:
        with open(filename, "rb") as f:  # Open in binary read mode
            # 1. Read the salt
            salt = f.read(32)  # Read 32 bytes for the salt

            # 2. Read the encrypted data
            encrypted_info = f.read()

    except FileNotFoundError:
        logging.error(f"Error: File not found: {filename}")
        return None
    except Exception as e:
        logging.error(f"Error reading file: {e}")
        return None

    # 3. Generate the encryption key from the password and salt
    key = generate_key(password, salt)

    # 4. Decrypt the data
    try:
        decrypted_info = decrypt_data(encrypted_info, key)
        return decrypted_info
    except Exception as e:
        logging.error(f"Decryption error: {e}")
        return None
    finally:
        # Securely erase the key from memory
        key = b'\0' * len(key)
        gc.collect()


if __name__ == "__main__":
    # Example Usage
    secret_data = "This is my super secret information.  It should be encrypted!"
    file_name = "my_secret_file.dat"

    # Get password from user prompt
    encryption_password = getpass.getpass("Enter encryption password: ")

    create_secure_file(file_name, secret_data, encryption_password)

    # Later, to read the file:
    decryption_password = getpass.getpass("Enter decryption password: ")
    decrypted_data = read_secure_file(file_name, decryption_password)

    # Securely erase the password from memory after use
    encryption_password = ""
    decryption_password = ""
    gc.collect()

    if decrypted_data:
        print("Decrypted data:", decrypted_data)

    # Example of how to manage dependencies using requirements.txt:
    # Create a requirements.txt file with the following content:
    # cryptography==<version>
    # Then, install the dependencies using: pip install -r requirements.txt

