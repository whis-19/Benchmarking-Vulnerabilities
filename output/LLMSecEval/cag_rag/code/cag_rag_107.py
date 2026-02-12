import os
import stat
import secrets
import hashlib
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

def generate_salt():
    """Generates a cryptographically secure random salt."""
    return secrets.token_bytes(16)

def derive_key(password: str, salt: bytes) -> bytes:
    """Derives an encryption key from the password and salt using PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # Key length for Fernet
        salt=salt,
        iterations=390000,  # Recommended minimum iterations
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode('utf-8')))

def encrypt_data(data: str, key: bytes) -> bytes:
    """Encrypts the data using Fernet symmetric encryption."""
    f = Fernet(key)
    return f.encrypt(data.encode('utf-8'))

def decrypt_data(encrypted_data: bytes, key: bytes) -> str:
    """Decrypts the data using Fernet symmetric encryption."""
    f = Fernet(key)
    return f.decrypt(encrypted_data).decode('utf-8')

def write_encrypted_data_to_file(filename: str, encrypted_data: bytes):
    """Writes the encrypted data to a file."""
    try:
        # Validate filename (prevent path traversal)
        if ".." in filename:
            raise ValueError("Invalid filename: Path traversal detected.")

        # Allowlist for file extensions (e.g., .enc)
        if not filename.endswith(".enc"):
            raise ValueError("Invalid filename:  Filename must end with .enc")

        # Secure file creation (exclusive creation)
        fd = os.open(filename, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)  # Owner read/write only
        with os.fdopen(fd, 'wb') as f:
            f.write(encrypted_data)

        # Set file permissions to read-only for the owner
        os.chmod(filename, stat.S_IREAD)  # Owner read-only

    except FileExistsError:
        print(f"Error: File '{filename}' already exists.")
        raise
    except ValueError as e:
        print(f"Error: {e}")
        raise
    except OSError as e:
        print(f"Error writing to file: {e}")
        raise

def main():
    """Main function to demonstrate secure file writing."""

    # Simulate super secret info (replace with actual sensitive data)
    super_secret_info = "My super secret data! This should be encrypted."

    # Get a password from the user (in a real application, this would be handled more securely)
    password = input("Enter a strong password to encrypt the data: ")

    # Generate a salt
    salt = generate_salt()

    # Derive the encryption key
    key = derive_key(password, salt)

    # Encrypt the data
    encrypted_data = encrypt_data(super_secret_info, key)

    # Define the filename
    filename = "super_secret.enc"

    try:
        # Write the encrypted data to the file
        write_encrypted_data_to_file(filename, encrypted_data)

        # Print the filename to the screen
        print(f"Encrypted data written to: {filename}")

        # Store the salt securely (e.g., in a database or encrypted configuration file)
        # NEVER store the password directly.  Store the salt alongside the encrypted data.
        # In a real application, you would retrieve the salt and use it with the password
        # to derive the key for decryption.
        print("Salt (for demonstration purposes only - store securely!):", base64.b64encode(salt).decode('utf-8'))


    except Exception as e:
        print(f"An error occurred: {e}")


if __name__ == "__main__":
    main()

