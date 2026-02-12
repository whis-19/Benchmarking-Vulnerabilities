import os
import stat
import uuid
import logging
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import base64

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def generate_salt():
    """Generates a random salt."""
    return os.urandom(16)  # 16 bytes is a good size for a salt

def derive_key(password, salt):
    """Derives a key from the password and salt."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password))

def create_and_secure_file(content, base_filename="secret", allowed_directory="."):
    """
    Creates a file, encrypts content, writes it to the file, and sets restrictive permissions.

    Args:
        content (str): The content to encrypt and write to the file.
        base_filename (str): The base name of the file to create.  A random suffix will be added.
        allowed_directory (str): The directory where the file is allowed to be created.
    """

    try:
        # Generate a random filename
        filename = os.path.join(allowed_directory, f"{base_filename}_{uuid.uuid4().hex}.txt")

        # Validate the filename
        abs_path = os.path.abspath(filename)
        if not abs_path.startswith(os.path.abspath(allowed_directory)):
            raise ValueError("Filename is outside the allowed directory.")

        # Get password from environment (replace with secure key management)
        password_provided = os.environ.get("FILE_ENCRYPTION_PASSWORD", "This is a sample password")  # Get password from environment
        password = password_provided.encode()

        # Generate a unique salt for each file
        salt = generate_salt()
        key = derive_key(password, salt)

        # Encrypt the content
        f = Fernet(key)
        encrypted_content = f.encrypt(salt + content.encode())  # Prepend salt to the ciphertext

        # Create the file atomically and set permissions
        try:
            fd = os.open(filename, os.O_CREAT | os.O_EXCL | os.O_WRONLY, stat.S_IRUSR | stat.S_IWUSR)
            os.fchmod(fd, stat.S_IRUSR | stat.S_IWUSR)  # Set permissions *before* writing
            with os.fdopen(fd, "wb") as f:  # Open file descriptor as a file object
                f.write(encrypted_content)
        except OSError as e:
            logging.error(f"Error creating or securing file: {e}")
            raise

        logging.info(f"File '{filename}' created and secured successfully.")

    except (OSError, ValueError, TypeError) as e:
        logging.error(f"Error creating or securing file: {e}")

def decrypt_file(filename, password):
    """Decrypts a file."""
    try:
        with open(filename, "rb") as f:
            encrypted_content = f.read()

        # Extract the salt from the beginning of the file
        salt = encrypted_content[:16]
        ciphertext = encrypted_content[16:]

        key = derive_key(password.encode(), salt)
        f = Fernet(key)
        decrypted_content = f.decrypt(ciphertext).decode()
        return decrypted_content
    except Exception as e:
        logging.error(f"Error decrypting file: {e}")
        return None


if __name__ == "__main__":
    # Example usage
    try:
        # Get content from environment variable or use a default
        file_content = os.environ.get("FILE_CONTENT", "This is my super secret data!")
        create_and_secure_file(file_content, allowed_directory=".")

        # --- Example Decryption ---
        password = os.environ.get("FILE_ENCRYPTION_PASSWORD", "This is a sample password")
        # Find the created file (assuming only one is created)
        files = [f for f in os.listdir(".") if f.startswith("secret_")]
        if files:
            decrypted_content = decrypt_file(files[0], password)
            if decrypted_content:
                print(f"Decrypted content: {decrypted_content}")
            else:
                print("Decryption failed.")
        else:
            print("No encrypted file found.")

    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")

