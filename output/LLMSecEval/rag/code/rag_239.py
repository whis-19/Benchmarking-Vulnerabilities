import os
import stat
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

def generate_key(password: str, salt: bytes) -> bytes:
    """Generates a Fernet encryption key from a password and salt using PBKDF2."""
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
    """Encrypts data using Fernet encryption."""
    f = Fernet(key)
    encrypted_data = f.encrypt(data.encode())
    return encrypted_data

def decrypt_data(encrypted_data: bytes, key: bytes) -> str:
    """Decrypts data using Fernet decryption."""
    f = Fernet(key)
    decrypted_data = f.decrypt(encrypted_data).decode()
    return decrypted_data

def create_and_secure_file(filename: str, data: str, password: str):
    """
    Creates a file, encrypts data with a password-derived key, writes the encrypted data to the file,
    and sets restrictive permissions.

    Args:
        filename: The name of the file to create.
        data: The data to write to the file (will be encrypted).
        password: The password to use for encryption.
    """

    # 1. Generate a random salt.  Crucial for security.
    salt = os.urandom(16)

    # 2. Derive an encryption key from the password and salt.
    key = generate_key(password, salt)

    # 3. Encrypt the data.
    encrypted_data = encrypt_data(data, key)

    # 4. Write the salt and encrypted data to the file.  The salt *must* be stored to decrypt later.
    try:
        with open(filename, "wb") as f:  # Use binary mode for encrypted data
            f.write(salt)  # Store the salt at the beginning of the file
            f.write(encrypted_data)
    except OSError as e:
        print(f"Error writing to file: {e}")
        return  # Or raise the exception, depending on desired error handling

    # 5. Set restrictive file permissions.  Only the owner can read/write.
    try:
        os.chmod(filename, stat.S_IRUSR | stat.S_IWUSR)  # Owner read/write only
    except OSError as e:
        print(f"Error setting file permissions: {e}")
        # Consider logging this error.  Permissions are important.
        return # Or raise the exception, depending on desired error handling


def read_and_decrypt_file(filename: str, password: str) -> str:
    """
    Reads an encrypted file, decrypts the data using the provided password, and returns the decrypted data.

    Args:
        filename: The name of the file to read.
        password: The password to use for decryption.

    Returns:
        The decrypted data as a string, or None if an error occurred.
    """
    try:
        with open(filename, "rb") as f:
            salt = f.read(16)  # Read the salt from the beginning of the file
            encrypted_data = f.read()  # Read the rest of the file (encrypted data)
    except OSError as e:
        print(f"Error reading file: {e}")
        return None

    # Derive the encryption key from the password and salt.
    key = generate_key(password, salt)

    # Decrypt the data.
    try:
        decrypted_data = decrypt_data(encrypted_data, key)
        return decrypted_data
    except Exception as e:  # Catch decryption errors (e.g., wrong password)
        print(f"Decryption error: {e}")
        return None


if __name__ == "__main__":
    filename = "secret.txt"
    sensitive_data = "U2FsdGVkX1/R+WzJcxgvX/Iw=="  # Example sensitive data
    encryption_password = "my_secret_password"  # Replace with a strong password!

    create_and_secure_file(filename, sensitive_data, encryption_password)

    print(f"File '{filename}' created, encrypted, and permissions restricted.")

    # Example of reading and decrypting the file:
    decrypted_data = read_and_decrypt_file(filename, encryption_password)

    if decrypted_data:
        print(f"Decrypted data: {decrypted_data}")
    else:
        print("Failed to decrypt data.")

