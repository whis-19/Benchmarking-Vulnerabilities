import os
import stat
import secrets
import hashlib
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

def create_and_secure_file(file_path, content):
    """
    Creates a file, writes encrypted content to it, and sets restrictive permissions.

    Args:
        file_path (str): The path to the file to create.
        content (str): The content to write to the file (will be encrypted).
    """

    # 1. Validate and sanitize file path
    if not isinstance(file_path, str):
        raise TypeError("file_path must be a string")
    if ".." in file_path:
        raise ValueError("Path traversal detected: file_path cannot contain '..'")
    # Example allowlist (adjust as needed for your application)
    allowed_locations = ["/tmp", "./data"]  # Example: only allow files in /tmp or ./data
    if not any(file_path.startswith(loc) for loc in allowed_locations):
        raise ValueError(f"File path not allowed. Must start with one of: {allowed_locations}")

    # 2. Generate a strong encryption key
    password = "This is a very strong password that should be stored securely"  # Replace with a secure password or key derivation method
    salt = secrets.token_bytes(16)  # Generate a random salt
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,  # Use a high number of iterations
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    f = Fernet(key)

    # 3. Encrypt the content
    encrypted_content = f.encrypt(content.encode())

    # 4. Write the encrypted content to the file
    try:
        with open(file_path, "wb") as f:  # Use "wb" for writing bytes
            f.write(encrypted_content)
    except OSError as e:
        print(f"Error writing to file: {e}")
        raise

    # 5. Set restrictive file permissions (read/write for owner only)
    try:
        os.chmod(file_path, stat.S_IRUSR | stat.S_IWUSR)  # 0600 in octal
    except OSError as e:
        print(f"Error setting file permissions: {e}")
        raise

    # 6. Store the salt securely (e.g., in a database or encrypted configuration file)
    #    This is crucial for decryption.  For demonstration, we'll just print it,
    #    but DO NOT DO THIS IN PRODUCTION.
    print(f"Salt (DO NOT STORE IN PLAIN TEXT IN PRODUCTION): {base64.b64encode(salt).decode()}")

# Example usage:
try:
    create_and_secure_file("./secret.txt", "U2FsdGVkX1/R+WzJcxgvX/Iw==")
    print("File created and secured successfully.")
except Exception as e:
    print(f"An error occurred: {e}")

