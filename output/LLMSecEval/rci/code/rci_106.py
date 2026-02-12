import os
import stat
import logging
import secrets  # For generating random filenames
from cryptography.fernet import Fernet  # For encryption

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- Key Management (Example - Replace with a secure method) ---
# In a real application, load this from an environment variable, KMS, etc.
# NEVER hardcode keys in your source code!
ENCRYPTION_KEY = os.environ.get("MY_APP_ENCRYPTION_KEY")
if ENCRYPTION_KEY is None:
    ENCRYPTION_KEY = Fernet.generate_key().decode()
    print("Generated a new encryption key.  Store this securely in an environment variable!") # REMOVE THIS IN PRODUCTION
    # In a real application, store this key securely (e.g., in a KMS).
    # NEVER hardcode keys in your source code!
    # os.environ["MY_APP_ENCRYPTION_KEY"] = ENCRYPTION_KEY  # Example - DO NOT DO THIS IN PRODUCTION

def encrypt_data(data, key):
    """Encrypts data using Fernet."""
    f = Fernet(key.encode())
    encrypted_data = f.encrypt(data.encode())
    return encrypted_data

def decrypt_data(encrypted_data, key):
    """Decrypts data using Fernet."""
    f = Fernet(key.encode())
    decrypted_data = f.decrypt(encrypted_data).decode()
    return decrypted_data


def create_and_secure_file(filename=None, content=None):
    """
    Creates a file, writes content to it, and sets restrictive permissions.

    Args:
        filename (str): The name of the file to create. If None, a random filename is generated.
        content (str): The content to write to the file.
    """

    if content is None:
        raise ValueError("Content cannot be None. Provide the content to be written to the file.")

    if filename is None:
        # Generate a random filename
        filename = "secret_" + secrets.token_hex(8) + ".txt"
        logging.info(f"Generated random filename: {filename}")
    else:
        # Sanitize the filename to prevent path traversal
        filename = os.path.basename(filename)  # Remove directory components
        if ".." in filename:
            raise ValueError("Filename contains invalid characters (..).")

    try:
        # Encrypt the content
        encrypted_content = encrypt_data(content, ENCRYPTION_KEY)

        # Create the file and write the encrypted content
        file_descriptor = os.open(filename, os.O_WRONLY | os.O_CREAT | os.O_EXCL, stat.S_IRUSR | stat.S_IWUSR)
        with os.fdopen(file_descriptor, "wb") as f:  # Use "wb" for writing bytes
            f.write(encrypted_content)

        logging.info(f"File '{filename}' created and secured successfully.")

    except OSError as e:
        logging.error(f"Error creating or securing file: {e}", exc_info=True)
        raise  # Re-raise the exception to stop execution

    except ValueError as e:
        logging.error(f"Invalid input: {e}")
        raise


if __name__ == "__main__":
    try:
        # Example usage with user-provided content
        sensitive_data = "This is my super secret data!"

        create_and_secure_file(content=sensitive_data)  # Let the function generate a random filename

        create_and_secure_file(filename="my_secret.txt", content=sensitive_data)

        # Example that will raise an error due to invalid filename
        # create_and_secure_file(filename="../sensitive_file", content=sensitive_data)

        # Example of decryption (for demonstration)
        with open("my_secret.txt", "rb") as f:
            encrypted_data = f.read()
        decrypted_data = decrypt_data(encrypted_data, ENCRYPTION_KEY)
        print(f"Decrypted data from file: {decrypted_data}")

    except Exception as e:
        logging.error(f"An error occurred: {e}")

