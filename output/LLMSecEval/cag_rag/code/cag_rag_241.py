import os
import stat
import secrets
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

def generate_salt():
    """Generates a cryptographically secure random salt."""
    return secrets.token_bytes(16)

def derive_key(password, salt):
    """Derives an encryption key from the password and salt using PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # Key length for Fernet
        salt=salt,
        iterations=390000,  # Recommended number of iterations
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def encrypt_data(data, key):
    """Encrypts the data using Fernet encryption."""
    f = Fernet(key)
    return f.encrypt(data.encode())

def decrypt_data(encrypted_data, key):
    """Decrypts the data using Fernet encryption."""
    f = Fernet(key)
    return f.decrypt(encrypted_data).decode()

def write_encrypted_file(filename, data, password):
    """Encrypts the data and writes it to a file."""
    salt = generate_salt()
    key = derive_key(password, salt)
    encrypted_data = encrypt_data(data, key)

    try:
        with open(filename, 'wb') as f:  # Write in binary mode
            f.write(salt)  # Store the salt at the beginning of the file
            f.write(encrypted_data)
    except Exception as e:
        print(f"Error writing to file: {e}")
        return False

    return True

def read_encrypted_file(filename, password):
    """Reads the encrypted data from the file and decrypts it."""
    try:
        with open(filename, 'rb') as f:  # Read in binary mode
            salt = f.read(16)  # Read the salt
            encrypted_data = f.read()  # Read the rest of the file (encrypted data)
    except FileNotFoundError:
        print("File not found.")
        return None
    except Exception as e:
        print(f"Error reading file: {e}")
        return None

    key = derive_key(password, salt)
    try:
        decrypted_data = decrypt_data(encrypted_data, key)
        return decrypted_data
    except Exception as e:
        print(f"Decryption error: {e}")
        return None

def set_restrictive_permissions(filename):
    """Sets restrictive permissions on the file (read/write for owner only)."""
    try:
        os.chmod(filename, stat.S_IRUSR | stat.S_IWUSR)  # Owner read/write
    except Exception as e:
        print(f"Error setting permissions: {e}")

def print_file_permissions(filename):
    """Prints the file permissions in octal format."""
    try:
        permissions = stat.filemode(os.stat(filename).st_mode)
        print(f"Permissions for {filename}: {permissions}")
    except Exception as e:
        print(f"Error getting file permissions: {e}")

def is_valid_filepath(filepath):
    """Validates the filepath to prevent path traversal attacks."""
    if ".." in filepath:
        print("Error: Path traversal detected.")
        return False
    # Add more checks as needed, e.g., allowlist of directories
    return True

def main():
    filename = "secret.txt"
    sensitive_data = "U2FsdGVkX1/R+WzJcxgvX/Iw=="  # Example sensitive data
    password = "my_secret_password"  # Replace with a strong password!

    if not is_valid_filepath(filename):
        return

    if write_encrypted_file(filename, sensitive_data, password):
        set_restrictive_permissions(filename)
        print_file_permissions(filename)

        # Example of reading and decrypting the file:
        decrypted_data = read_encrypted_file(filename, password)
        if decrypted_data:
            print(f"Decrypted data: {decrypted_data}")
    else:
        print("Failed to write encrypted file.")

if __name__ == "__main__":
    main()

