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
        sensitive_data (str): The sensitive data to encrypt and store.
        password (str): The password to use for encryption.
    """

    # 1. Validate and sanitize file path (Prevent path traversal)
    if ".." in file_path:
        raise ValueError("Invalid file path: Path traversal detected.")

    # 2. Allowlist for file extensions (optional, but recommended)
    allowed_extensions = [".txt", ".dat", ".config"]  # Example
    _, file_extension = os.path.splitext(file_path)
    if file_extension.lower() not in allowed_extensions:
        print(f"Warning: File extension '{file_extension}' is not in the allowlist.")
        # Consider raising an exception or logging the event.

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
        with open(file_path, "wb") as f:  # Use "wb" for writing bytes
            f.write(salt)  # Store the salt
            f.write(encrypted_data)

        # 6. Set restrictive file permissions (owner read/write only)
        os.chmod(file_path, stat.S_IRUSR | stat.S_IWUSR)  # 0600 in octal

        # 7. Print file permissions (for verification)
        permissions = stat.filemode(os.stat(file_path).st_mode)
        print(f"File permissions for {file_path}: {permissions}")

    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        pass # No need to explicitly close the file, 'with' statement handles it.


# Example usage:
file_path = "secret.txt"
sensitive_data = "U2FsdGVkX1/R+WzJcxgvX/Iw=="  # Example sensitive data
password = "my_secret_password"  # Replace with a strong password

create_and_secure_file(file_path, sensitive_data, password)


# Example of how to decrypt the data (separate function for clarity)
def decrypt_file(file_path, password):
    """Decrypts the data in the file."""
    try:
        with open(file_path, "rb") as f:
            salt = f.read(16)
            encrypted_data = f.read()

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=390000,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))

        f = Fernet(key)
        decrypted_data = f.decrypt(encrypted_data).decode()
        return decrypted_data

    except Exception as e:
        print(f"Decryption error: {e}")
        return None


# Example of decrypting the file
decrypted_data = decrypt_file(file_path, password)
if decrypted_data:
    print(f"Decrypted data: {decrypted_data}")

