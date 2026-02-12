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
        iterations=390000,  # Recommended number of iterations
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

        # Allowlist for file extensions (example: only allow .enc)
        if not filename.endswith(".enc"):
            raise ValueError("Invalid filename:  Only .enc files are allowed.")

        # Define allowed directory (optional, for extra security)
        allowed_directory = "/tmp"  # Or another secure location
        if not os.path.abspath(os.path.dirname(filename)).startswith(allowed_directory):
            raise ValueError(f"Invalid filename: File must be in {allowed_directory}")

        filepath = os.path.join(allowed_directory, filename) # Ensure file is written to allowed directory

        with open(filepath, "wb") as f:  # Write in binary mode
            f.write(encrypted_data)

        # Set file permissions to read-only for the owner
        os.chmod(filepath, stat.S_IREAD)

        print(f"Encrypted data written to: {filepath}")

    except ValueError as e:
        print(f"Error writing to file: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

def main():
    """Main function to demonstrate the secure file writing process."""

    # 1.  Get super secret info (replace with actual secure retrieval)
    super_secret_info = "This is my super secret information that needs to be protected."

    # 2.  Get a password from the user (in a real application, use a more secure method)
    password = input("Enter a strong password: ")

    # 3. Generate a salt
    salt = generate_salt()

    # 4. Derive the encryption key
    key = derive_key(password, salt)

    # 5. Encrypt the data
    encrypted_data = encrypt_data(super_secret_info, key)

    # 6. Write the encrypted data to a file
    filename = "super_secret.enc"  # Use .enc extension
    write_encrypted_data_to_file(filename, encrypted_data)

    # Example of decryption (for demonstration purposes only)
    # In a real application, decryption should be handled with extreme care
    # and only when absolutely necessary.
    try:
        with open(os.path.join("/tmp", filename), "rb") as f:
            read_encrypted_data = f.read()
        decrypted_data = decrypt_data(read_encrypted_data, key)
        print("Decrypted data:", decrypted_data)
    except Exception as e:
        print(f"Error decrypting data: {e}")

if __name__ == "__main__":
    main()

