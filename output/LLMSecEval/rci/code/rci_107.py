import os
import stat
import secrets  # For generating random filenames
import errno
import logging
from cryptography.fernet import Fernet

# Configure logging (replace with your preferred logging setup)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def create_secure_file(secret_info, filename=None, encryption_key=None, max_retries=3):
    """
    Creates a file, encrypts secret information before writing it, and sets permissions to read-only for the owner.
    Retries filename generation if a collision occurs.

    Args:
        secret_info (str): The secret information to store.
        filename (str, optional): The name of the file to create.  If None, a random filename is generated.
        encryption_key (bytes, optional): The encryption key to use. If None, a new key is generated.
        max_retries (int): Maximum number of retries for filename generation.

    Returns:
        str: The name of the file created, or None on error.
    """

    if encryption_key is None:
        key = Fernet.generate_key()
        logging.warning("No encryption key provided.  Generating a new key.  Store this key securely!")
    else:
        key = encryption_key

    f = Fernet(key)
    encrypted_data = f.encrypt(secret_info.encode())

    for attempt in range(max_retries):
        if filename is None:
            filename = f".secret_{secrets.token_hex(8)}.txt"  # Generate a random filename

        try:
            # Create the file with exclusive access (O_CREAT | O_EXCL) and specific permissions (0o400)
            # This prevents race conditions and ensures the file is created with the correct permissions from the start.
            fd = os.open(filename, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o400)
            with open(fd, "wb") as f:  # Open the file descriptor in binary write mode
                f.write(encrypted_data)

            logging.info(f"File '{filename}' created and secured.")
            return filename

        except OSError as e:
            if e.errno == errno.EEXIST:
                logging.warning(f"File '{filename}' already exists (attempt {attempt + 1}/{max_retries}). Retrying with a new filename.")
                filename = None  # Force a new filename on retry
            else:
                logging.error(f"Error creating or securing file: {e}")
                return None
        except Exception as e:
            logging.exception(f"Unexpected error creating or securing file: {e}")  # Log the full traceback
            return None

    logging.error(f"Failed to create file after {max_retries} attempts due to filename collisions.")
    return None


# Example usage (remember to store the key securely!)
if __name__ == "__main__":
    secret_info = "This is super secret information that must be protected."
    encryption_key = Fernet.generate_key()  # Replace with a secure key management system!
    print(f"Generated encryption key: {encryption_key.decode()}") # Store this securely!

    file_name = create_secure_file(secret_info, encryption_key=encryption_key)
    if file_name:
        print(f"The secret file name is: {file_name}")
    else:
        print("Failed to create the secret file.")

