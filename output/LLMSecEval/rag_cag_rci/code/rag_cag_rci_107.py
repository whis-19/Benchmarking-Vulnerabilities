import os
import stat
import secrets
import hashlib
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

def generate_key(password: str, salt: bytes) -> bytes:
    """
    Generates a Fernet encryption key from a password and salt using PBKDF2HMAC.

    Args:
        password: The password to derive the key from.
        salt: A random salt.

    Returns:
        A 32-byte encryption key.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,  # Recommended minimum iterations
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key


def encrypt_data(data: str, key: bytes) -> bytes:
    """
    Encrypts data using Fernet symmetric encryption.

    Args:
        data: The data to encrypt.
        key: The encryption key.

    Returns:
        The encrypted data.
    """
    f = Fernet(key)
    encrypted_data = f.encrypt(data.encode())
    return encrypted_data


def decrypt_data(encrypted_data: bytes, key: bytes) -> str:
    """
    Decrypts data using Fernet symmetric encryption.

    Args:
        encrypted_data: The encrypted data.
        key: The encryption key.

    Returns:
        The decrypted data as a string.
    """
    f = Fernet(key)
    decrypted_data = f.decrypt(encrypted_data).decode()
    return decrypted_data


def create_and_secure_file(sensitive_info: str, filename: str = "secret.dat") -> str:
    """
    Creates a file, encrypts sensitive information, writes it to the file,
    and sets the file permissions to read-only for the owner.

    Args:
        sensitive_info: The sensitive information to store.
        filename: The name of the file to create.  Defaults to "secret.dat".

    Returns:
        The name of the file created.

    Raises:
        ValueError: If the filename contains invalid characters or path traversal attempts.
        OSError: If there are issues creating or modifying the file.
    """

    # 1. Validate and Sanitize Filename
    if not filename.isalnum() and "." not in filename:
        raise ValueError("Invalid filename: Filename must be alphanumeric and contain an extension.")

    if ".." in filename:
        raise ValueError("Invalid filename: Path traversal detected.")

    # 2.  Allowlist file extension (example: only allow .dat files)
    if not filename.endswith(".dat"):
        raise ValueError("Invalid file extension: Only .dat files are allowed.")

    # 3. Generate a strong encryption key
    password = secrets.token_urlsafe(32)  # Generate a random password
    salt = os.urandom(16)  # Generate a random salt
    key = generate_key(password, salt)

    # 4. Encrypt the sensitive information
    encrypted_data = encrypt_data(sensitive_info, key)

    # 5. Write the encrypted data, salt, and password to the file
    try:
        with open(filename, "wb") as f:  # Open in binary write mode
            f.write(salt)
            f.write(password.encode())
            f.write(encrypted_data)
    except OSError as e:
        raise OSError(f"Error writing to file: {e}")

    # 6. Set file permissions to read-only for the owner
    try:
        os.chmod(filename, stat.S_IRUSR)  # Read-only for owner
    except OSError as e:
        raise OSError(f"Error changing file permissions: {e}")

    return filename


if __name__ == "__main__":
    super_secret_info = "This is some highly sensitive information that needs to be protected."

    try:
        file_name = create_and_secure_file(super_secret_info)
        print(f"Successfully created and secured file: {file_name}")

        # Example of how to read and decrypt the file (for demonstration purposes only)
        # In a real application, you would need to securely store the password and salt.
        # This example is NOT secure for production use.
        with open(file_name, "rb") as f:
            salt = f.read(16)
            password = f.read(44).decode()
            encrypted_data = f.read()

        key = generate_key(password, salt)
        decrypted_info = decrypt_data(encrypted_data, key)
        print(f"Decrypted information: {decrypted_info}")

    except ValueError as e:
        print(f"Error: {e}")
    except OSError as e:
        print(f"Error: {e}")

