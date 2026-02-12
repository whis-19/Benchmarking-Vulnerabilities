import os
import stat
import subprocess
import secrets
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import logging  # For secure logging

# Configure logging (replace with your desired logging setup)
logging.basicConfig(level=logging.INFO, filename="encryption.log", format='%(asctime)s - %(levelname)s - %(message)s')


def secure_store_key(key, key_id):
    """
    Securely stores the encryption key.  This is a placeholder function.

    In a real application, you would use a Key Management System (KMS),
    a Hardware Security Module (HSM), or another secure storage mechanism.

    Args:
        key (bytes): The encryption key to store.
        key_id (str):  An identifier for the key (e.g., filename, UUID).

    Raises:
        NotImplementedError:  This function must be implemented with a real key storage solution.
    """
    raise NotImplementedError("Secure key storage must be implemented using a KMS, HSM, or other secure mechanism.")


def create_encrypted_file(filename="secret.enc", content="This is a secret message.", password=None):
    """
    Creates an encrypted file using Fernet encryption with a key derived from a password.

    Args:
        filename (str): The name of the encrypted file to create. Defaults to "secret.enc".
        content (str): The content to encrypt and write to the file. Defaults to "This is a secret message.".
        password (str): The password to use for key derivation. If None, a random key is generated.
                         DO NOT HARDCODE IN PRODUCTION.  Prompt the user or use a secure method.
    """
    try:
        # Validate filename (basic example - improve as needed)
        if ".." in filename or "/" in filename:
            raise ValueError("Invalid filename: Filename cannot contain '..' or '/'")

        # Generate a salt
        salt = os.urandom(16)

        if password is None:
            # Generate a random key if no password is provided
            key = Fernet.generate_key()
            print("Generated a random encryption key.  Storing it securely...") # IMPORTANT: Handle this key securely!
            try:
                secure_store_key(key, filename)  # Use a secure key storage mechanism!
            except NotImplementedError:
                print("ERROR: Secure key storage is not implemented!  The key has not been stored securely.")
                return None  # Or raise an exception

        else:
            # Derive a key from the password using PBKDF2
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=390000,  # Recommended minimum is 100000, but higher is better
                backend=default_backend()
            )
            key = base64.urlsafe_b64encode(kdf.derive(password.encode()))

        # Create a Fernet cipher object
        f = Fernet(key)

        # Encrypt the content
        encrypted_content = f.encrypt(content.encode())

        # Write the salt and encrypted content to the file
        with open(filename, "wb") as f:  # Open in binary mode
            f.write(salt)
            f.write(encrypted_content)

        # Restrict permissions to owner read/write only (0600)
        os.chmod(filename, stat.S_IRUSR | stat.S_IWUSR)

        # Print the permissions of the file using stat
        st = os.stat(filename)
        permissions = oct(st.st_mode & 0o777)  # Extract permissions in octal format
        print(f"Permissions of {filename}: {permissions}")

        if password is None:
            return None  # Key is stored securely, not returned
        else:
            return key  # Return the key for later decryption (handle securely!)

    except OSError as e:
        logging.exception("Error creating or modifying file:")  # Log the full exception
        print(f"Error: Could not create or modify file. See log for details.") # Generic error message
        return None
    except ValueError as e:
        print(f"Error: {e}")
        return None
    except Exception as e:
        logging.exception("An unexpected error occurred:")  # Log the full exception
        print(f"An unexpected error occurred. See log for details.") # Generic error message
        return None


def decrypt_file(filename="secret.enc", password=None, key=None):
    """
    Decrypts a file encrypted with create_encrypted_file.

    Args:
        filename (str): The name of the encrypted file. Defaults to "secret.enc".
        password (str): The password used for encryption.  DO NOT HARDCODE IN PRODUCTION.
        key (bytes): The encryption key.  Required if a random key was used for encryption.
    """
    try:
        # Validate filename (basic example - improve as needed)
        if ".." in filename or "/" in filename:
            raise ValueError("Invalid filename: Filename cannot contain '..' or '/'")

        with open(filename, "rb") as f:  # Open in binary mode
            salt = f.read(16)
            encrypted_content = f.read()

        if key is None:
            if password is None:
                raise ValueError("Either password or key must be provided for decryption.")

            # Derive the key from the password and salt
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=390000,
                backend=default_backend()
            )
            key = base64.urlsafe_b64encode(kdf.derive(password.encode()))

        # Create a Fernet cipher object
        f = Fernet(key)

        # Decrypt the content
        decrypted_content = f.decrypt(encrypted_content).decode()

        print(f"Decrypted content: {decrypted_content}")

    except OSError as e:
        logging.exception("Error reading file:")  # Log the full exception
        print(f"Error: Could not read file. See log for details.") # Generic error message
    except ValueError as e:
        print(f"Error: {e}")
    except Exception as e:
        logging.exception("Error during decryption:")  # Log the full exception
        print(f"Error during decryption. See log for details.") # Generic error message


if __name__ == "__main__":
    # Example usage:
    # Example using a password:
    password = "my_secret_password"  # NEVER HARDCODE IN PRODUCTION!
    key = create_encrypted_file(filename="secret_password.enc", password=password)
    if key:
        decrypt_file(filename="secret_password.enc", password=password)

    # Example using a randomly generated key:
    key = create_encrypted_file(filename="secret_random.enc")
    if key:
        #  This is where you would SECURELY store the key!
        #  For example:
        #  secure_store_key(key, "secret_random.enc")
        #  Then, to decrypt:
        #  retrieved_key = secure_retrieve_key("secret_random.enc")
        #  if retrieved_key:
        #      decrypt_file(filename="secret_random.enc", key=retrieved_key)
        print("Key generated, but secure storage is not implemented.  Cannot decrypt.")
    else:
        print("Failed to create encrypted file.")

