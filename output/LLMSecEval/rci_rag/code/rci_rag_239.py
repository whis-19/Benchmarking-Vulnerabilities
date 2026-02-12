import os
import stat
import secrets  # For secure random number generation
from cryptography.fernet import Fernet  # For symmetric encryption
import logging  # For logging events
import os

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def create_and_secure_file(filename="secret.txt", content="U2FsdGVkX1/R+WzJcxgvX/Iw=="):
    """
    Creates a file with sensitive content and restricts its permissions.

    Args:
        filename (str): The name of the file to create. Defaults to "secret.txt".
        content (str): The content to write to the file. Defaults to "U2FsdGVkX1/R+WzJcxgvX/Iw==".
    """

    try:
        # Validate filename
        filename = os.path.basename(filename)  # Prevent path traversal
        if not filename:
            raise ValueError("Invalid filename.")

        # Generate a random encryption key
        key = Fernet.generate_key()
        f = Fernet(key)
        encrypted_content = f.encrypt(content.encode())

        # Write the encrypted content to the file
        old_umask = os.umask(0o077)  # Set umask to 077 (owner-only permissions)
        try:
            with open(filename, "wb") as file:  # Open in binary write mode
                file.write(encrypted_content)

            # Restrict file permissions to owner read/write only (0o600)
            os.chmod(filename, stat.S_IRUSR | stat.S_IWUSR)  # Equivalent to 0o600
        finally:
            os.umask(old_umask)  # Restore the original umask


        logging.info(f"File '{filename}' created and permissions restricted successfully.")
        # NEVER DO THIS IN PRODUCTION:
        #logging.info(f"Encryption key: {key.decode()}") #DO NOT DO THIS IN PRODUCTION.  This is for demonstration only.
        # Instead, store the key securely using a KMS, HSM, or OS keychain.

    except OSError as e:
        logging.error(f"Error creating or securing file: {e}")
    except ValueError as e:
        logging.error(f"Invalid input: {e}")
    except Exception as e:
        logging.exception(f"An unexpected error occurred: {e}")  # Log the full traceback


if __name__ == "__main__":
    create_and_secure_file()

# Security Considerations (Beyond this Code):

# ... (Existing Security Considerations) ...

# Specific Encryption Libraries:
#   - cryptography: A comprehensive library for cryptographic primitives.
#   - PyCryptodome: A fork of PyCrypto with enhancements and bug fixes.

# Secure Random Number Generation:
#   - Use the 'secrets' module for generating cryptographically secure random numbers
#     for keys, salts, and other security-sensitive data.  For example:
#       random_key = secrets.token_bytes(32)  # Generate a 32-byte random key

# Context Manager for chmod (Advanced):
#   - While not strictly necessary here, you can use a try...finally block to
#     ensure that file permissions are reverted to a safer state if an error occurs.
#     This is more relevant when temporarily relaxing permissions for a specific operation.

# Key Management:
#   - NEVER store the encryption key in the code or in the same file as the encrypted data.
#   - Consider using a Hardware Security Module (HSM), Key Management System (KMS),
#     or operating system keychain to store the key securely.
#   - For demonstration purposes only, the key is printed to the console.  DO NOT DO THIS IN PRODUCTION.

# Secure Deletion:
#   - When the file is no longer needed, securely delete it to prevent data recovery.
#   - Use a secure deletion tool or library to overwrite the file's contents multiple times.

