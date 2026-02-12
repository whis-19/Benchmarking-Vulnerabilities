import os
import stat
import secrets
import hashlib
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

def create_and_secure_file(file_path, sensitive_data, password):
    """
    Creates a file, encrypts sensitive data, writes it to the file,
    sets restrictive permissions, and prints the permissions.

    Args:
        file_path (str): The path to the file to create.
        sensitive_data (str): The sensitive data to store in the file.
        password (str): The password to use for encryption.
    """

    # 1. Validate and sanitize file path (Prevent path traversal)
    if ".." in file_path:
        raise ValueError("Invalid file path: Path traversal detected.")

    # 2.  Allowlist for file extensions (optional, but recommended)
    allowed_extensions = [".txt", ".dat", ".config"]  # Example
    _, file_extension = os.path.splitext(file_path)
    if file_extension.lower() not in allowed_extensions:
        print(f"Warning: File extension '{file_extension}' is not in the allowlist.")
        # Consider raising an exception or logging a warning if strict enforcement is needed.

    # 3. Key Derivation (instead of storing the password directly)
    salt = secrets.token_bytes(16)  # Generate a random salt
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # Key length for Fernet
        salt=salt,
        iterations=390000,  # Recommended number of iterations
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))

    # 4. Encryption using Fernet (symmetric encryption)
    f = Fernet(key)
    encrypted_data = f.encrypt(sensitive_data.encode())

    try:
        # 5. Create and write to the file
        with open(file_path, "wb") as f:  # Use "wb" for writing binary data
            f.write(salt)  # Store the salt
            f.write(encrypted_data)

        # 6. Set restrictive file permissions (owner read/write only)
        os.chmod(file_path, stat.S_IRUSR | stat.S_IWUSR)

        # 7. Print file permissions (for verification)
        permissions = stat.filemode(os.stat(file_path).st_mode)
        print(f"File permissions for {file_path}: {permissions}")

    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        pass # No explicit file closing needed as 'with' statement handles it.


def read_and_decrypt_file(file_path, password):
    """
    Reads an encrypted file, decrypts the data, and returns it.

    Args:
        file_path (str): The path to the encrypted file.
        password (str): The password used for encryption.

    Returns:
        str: The decrypted data, or None if an error occurred.
    """
    try:
        with open(file_path, "rb") as f:
            salt = f.read(16)
            encrypted_data = f.read()

        # Key Derivation (same as in create_and_secure_file)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,  # Key length for Fernet
            salt=salt,
            iterations=390000,  # Recommended number of iterations
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))

        f = Fernet(key)
        decrypted_data = f.decrypt(encrypted_data).decode()
        return decrypted_data

    except Exception as e:
        print(f"An error occurred during decryption: {e}")
        return None


# Example Usage
file_path = "secret.txt"
sensitive_data = "This is a highly sensitive secret."
password = "my_secret_password"  # Replace with a strong password!

create_and_secure_file(file_path, sensitive_data, password)

# Example of reading and decrypting the file
decrypted_data = read_and_decrypt_file(file_path, password)
if decrypted_data:
    print(f"Decrypted data: {decrypted_data}")

