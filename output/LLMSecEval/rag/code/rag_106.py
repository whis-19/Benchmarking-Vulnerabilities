import os
import stat
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

def generate_key(password: str, salt: bytes) -> bytes:
    """
    Generates a Fernet encryption key from a password and salt using PBKDF2HMAC.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # Fernet key size is 32 bytes
        salt=salt,
        iterations=390000,  # Recommended minimum iterations
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key


def encrypt_data(data: str, key: bytes) -> bytes:
    """
    Encrypts data using Fernet encryption.
    """
    f = Fernet(key)
    encrypted_data = f.encrypt(data.encode())
    return encrypted_data


def decrypt_data(encrypted_data: bytes, key: bytes) -> str:
    """
    Decrypts data using Fernet encryption.
    """
    f = Fernet(key)
    decrypted_data = f.decrypt(encrypted_data).decode()
    return decrypted_data


def create_secure_file(filename: str, data: str, password: str):
    """
    Creates a file, encrypts data with a key derived from a password,
    writes the encrypted data to the file, and sets restrictive permissions.
    """

    # Generate a random salt
    salt = os.urandom(16)

    # Generate the encryption key from the password and salt
    key = generate_key(password, salt)

    # Encrypt the data
    encrypted_data = encrypt_data(data, key)

    try:
        with open(filename, "wb") as f:  # Open in binary write mode
            # Store the salt and encrypted data in the file
            f.write(salt)
            f.write(encrypted_data)

        # Restrict file permissions (read/write for owner only)
        os.chmod(filename, stat.S_IRUSR | stat.S_IWUSR)

    except Exception as e:
        print(f"Error creating or securing file: {e}")


def read_secure_file(filename: str, password: str) -> str:
    """
    Reads an encrypted file, decrypts the data using a key derived from a password,
    and returns the decrypted data.
    """
    try:
        with open(filename, "rb") as f:  # Open in binary read mode
            # Read the salt from the beginning of the file
            salt = f.read(16)
            # Read the rest of the file as the encrypted data
            encrypted_data = f.read()

        # Generate the encryption key from the password and salt
        key = generate_key(password, salt)

        # Decrypt the data
        decrypted_data = decrypt_data(encrypted_data, key)
        return decrypted_data

    except Exception as e:
        print(f"Error reading or decrypting file: {e}")
        return None


if __name__ == "__main__":
    filename = "secret.txt"
    sensitive_data = "U2FsdGVkX1/R+WzJcxgvX/Iw=="  # Example sensitive data
    encryption_password = "my_secret_password"  # Replace with a strong password!

    # Create and secure the file
    create_secure_file(filename, sensitive_data, encryption_password)
    print(f"File '{filename}' created and secured.")

    # Read and decrypt the file (example)
    decrypted_data = read_secure_file(filename, encryption_password)
    if decrypted_data:
        print(f"Decrypted data: {decrypted_data}")

