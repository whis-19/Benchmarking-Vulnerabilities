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
        file_path (str): The path to the file to create.  Must be validated.
        content (str): The content to write to the file (will be encrypted).
    """

    # Validate file path (prevent path traversal)
    if ".." in file_path:
        raise ValueError("Invalid file path: Path traversal detected.")

    # Allowlist file extension (example: only allow .txt files)
    if not file_path.endswith(".txt"):
        raise ValueError("Invalid file extension: Only .txt files are allowed.")

    # Define the allowed directory (example: only allow files in /safe/directory)
    allowed_directory = "/safe/directory"  # Replace with your actual allowed directory
    if not os.path.abspath(os.path.dirname(file_path)).startswith(allowed_directory):
        raise ValueError(f"Invalid file path: File must be in {allowed_directory}")

    # Generate a strong encryption key using Fernet
    encryption_key = generate_encryption_key("my_secret_password") # Replace with a strong, securely stored password/key
    cipher = Fernet(encryption_key)

    # Encrypt the content
    encrypted_content = cipher.encrypt(content.encode())

    try:
        # Create the file and write the encrypted content
        with open(file_path, "wb") as f:  # Use "wb" for writing binary data
            f.write(encrypted_content)

        # Set restrictive file permissions (read/write for owner only)
        os.chmod(file_path, stat.S_IRUSR | stat.S_IWUSR)

    except OSError as e:
        print(f"Error creating or securing file: {e}")
        raise  # Re-raise the exception to signal failure

def generate_encryption_key(password: str) -> bytes:
    """Generates a Fernet encryption key from a password using PBKDF2HMAC."""

    password_bytes = password.encode('utf-8')
    salt = secrets.token_bytes(16)  # Generate a random salt
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # Fernet key size is 32 bytes
        salt=salt,
        iterations=390000,  # Use a high number of iterations
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password_bytes))

    # Store the salt securely (e.g., in the same encrypted configuration file as the key, or in a separate secure location).
    # In a real application, you would NOT hardcode the salt.  This is just for demonstration.
    # Example:  store_salt_securely(salt)

    return key

# Example usage (replace with your actual file path and content)
try:
    create_and_secure_file("/safe/directory/secret.txt", "U2FsdGVkX1/R+WzJcxgvX/Iw==")
    print("File created and secured successfully.")
except ValueError as e:
    print(f"Error: {e}")
except OSError as e:
    print(f"Error: {e}")

