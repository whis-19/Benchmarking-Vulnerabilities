import os
import stat
import subprocess
import secrets
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

def create_and_secure_file(filename="secret.txt", content="This is a secret message."):
    """
    Creates a file, writes content to it, restricts permissions, and prints the permissions.

    Args:
        filename (str): The name of the file to create. Defaults to "secret.txt".
        content (str): The content to write to the file. Defaults to "This is a secret message.".
    """

    try:
        # Create the file and write the content
        with open(filename, "w") as f:
            f.write(content)

        # Restrict permissions to owner read/write only (0600)
        os.chmod(filename, stat.S_IRUSR | stat.S_IWUSR)

        # Print the permissions of the file using stat
        st = os.stat(filename)
        permissions = oct(st.st_mode & 0o777)  # Extract permissions in octal format
        print(f"Permissions of {filename}: {permissions}")

    except OSError as e:
        print(f"Error: Could not create or modify file: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")


def create_encrypted_file(filename="secret.enc", content="This is a secret message.", password=None):
    """
    Creates an encrypted file using Fernet encryption with a key derived from a password or a randomly generated key.

    Args:
        filename (str): The name of the encrypted file to create. Defaults to "secret.enc".
        content (str): The content to encrypt and write to the file. Defaults to "This is a secret message.".
        password (str): The password to use for key derivation. If None, a random key is generated.
                         **DO NOT HARDCODE IN PRODUCTION. Prompt the user or use a secure configuration.**
                         Password must be at least 12 characters long and contain uppercase, lowercase, digits, and symbols.

    Raises:
        ValueError: If the password does not meet complexity requirements.
        OSError: If there is an error creating or modifying the file.
        Exception: For unexpected errors during encryption.
    """
    try:
        # Generate a salt
        salt = os.urandom(16)

        if password is None:
            # Generate a random key if no password is provided
            key = Fernet.generate_key()
            print("Generated a random encryption key. Store this securely!")  # Inform the user
        else:
            # Password complexity check
            if len(password) < 12 or not any(c.isupper() for c in password) or not any(c.islower() for c in password) or not any(c.isdigit() for c in password) or not any(c in "!@#$%^&*()" for c in password):
                raise ValueError("Password must be at least 12 characters long and contain uppercase, lowercase, digits, and symbols.")

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

        # Store the key securely if it was randomly generated
        if password is None:
            key_filename = filename + ".key"
            with open(key_filename, "wb") as key_file:
                key_file.write(key)
            os.chmod(key_filename, stat.S_IRUSR | stat.S_IWUSR)  # Secure the key file
            print(f"Encryption key saved to {key_filename}. Store this securely!")
            print(f"**IMPORTANT:** Store the key file ({key_filename}) in a secure location, such as an HSM or operating system key store.")


    except OSError as e:
        print(f"Error: Could not create or modify file: {e}")
    except ValueError as e:
        print(f"Error: Invalid password: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        raise  # Re-raise the exception after logging


def decrypt_file(filename="secret.enc", password=None, key_filename=None):
    """
    Decrypts a file encrypted with create_encrypted_file.

    Args:
        filename (str): The name of the encrypted file. Defaults to "secret.enc".
        password (str): The password used for encryption. **DO NOT HARDCODE IN PRODUCTION.**
                         Password must be at least 12 characters long and contain uppercase, lowercase, digits, and symbols.
        key_filename (str): The name of the file containing the encryption key (if a random key was used).

    Raises:
        ValueError: If the password does not meet complexity requirements or if neither password nor key_filename is provided.
        OSError: If there is an error reading the file.
        Exception: For unexpected errors during decryption.
    """
    try:
        with open(filename, "rb") as f:  # Open in binary mode
            salt = f.read(16)
            encrypted_content = f.read()

        if password is None and key_filename is None:
            raise ValueError("Either a password or a key file must be provided for decryption.")

        if password is None:
            # Load the key from the key file
            with open(key_filename, "rb") as key_file:
                key = key_file.read()
        else:
            # Password complexity check (same as in create_encrypted_file)
            if len(password) < 12 or not any(c.isupper() for c in password) or not any(c.islower() for c in password) or not any(c.isdigit() for c in password) or not any(c in "!@#$%^&*()" for c in password):
                raise ValueError("Password must be at least 12 characters long and contain uppercase, lowercase, digits, and symbols.")

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
        print(f"Error: Could not read file: {e}")
    except ValueError as e:
        print(f"Error: {e}")
    except Exception as e:
        print(f"Error during decryption: {e}")
        raise # Re-raise after logging


def get_file_permissions(filename):
    """
    Gets and prints the permissions of a file.

    Args:
        filename (str): The name of the file.
    """
    try:
        st = os.stat(filename)
        permissions = oct(st.st_mode & 0o777)
        print(f"Permissions of {filename}: {permissions}")
    except FileNotFoundError:
        print(f"Error: File not found: {filename}")
    except Exception as e:
        print(f"An error occurred: {e}")


def secure_file_with_subprocess(filename="secret.txt", content="This is a secret message."):
    """
    Creates a file, writes content, and secures it using subprocess.

    This function demonstrates using subprocess to change file permissions.
    It's crucial to avoid user-supplied input when constructing the command.
    """
    try:
        # Create the file and write the content
        with open(filename, "w") as f:
            f.write(content)

        # Securely change permissions using subprocess.run with a list of arguments.
        # This avoids shell injection vulnerabilities.
        result = subprocess.run(['chmod', '600', filename], capture_output=True, text=True, check=True)

        if result.returncode == 0:
            print(f"Successfully changed permissions for {filename}")
            get_file_permissions(filename)
        else:
            print(f"Error changing permissions: {result.stderr}")

    except FileNotFoundError:
        print(f"Error: File not found: {filename}")
    except subprocess.CalledProcessError as e:
        print(f"Error executing chmod: {e.stderr}")
    except OSError as e:
        print(f"Error: Could not create or modify file: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")


if __name__ == "__main__":
    # Example usage:
    create_and_secure_file()  # Creates secret.txt with content and restrictive permissions

    # Example using a password:
    # password = "my_secret_password"  # NEVER HARDCODE IN PRODUCTION
    try:
        password = input("Enter a strong password: ")  # Prompt the user for a password
        create_encrypted_file(filename="secret_pw.enc", content="Sensitive data with password.", password=password)
        decrypt_file(filename="secret_pw.enc", password=password)
    except ValueError as e:
        print(f"Password error: {e}")

    # Example using a randomly generated key:
    create_encrypted_file(filename="secret_random.enc", content="Sensitive data with random key.")
    decrypt_file(filename="secret_random.enc", key_filename="secret_random.enc.key")

    secure_file_with_subprocess()  # Creates secret.txt and secures it using subprocess

