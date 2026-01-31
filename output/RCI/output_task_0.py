import cryptography
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os
import base64

def generate_salt():
    """Generates a random salt for key derivation."""
    return os.urandom(16)

def derive_key(password, salt):
    """Derives a strong key from a password and salt using PBKDF2HMAC."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 32 bytes for AES256
        salt=salt,
        iterations=100000,  # High iteration count
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_data(data, key):
    """Encrypts data using AES256-CBC with PKCS7 padding."""
    iv = os.urandom(16)  # Initialization vector
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data.encode()) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return base64.b64encode(iv + ciphertext) # Store IV with ciphertext

def decrypt_data(ciphertext, key):
    """Decrypts data encrypted with AES256-CBC and PKCS7 padding."""
    decoded_ciphertext = base64.b64decode(ciphertext)
    iv = decoded_ciphertext[:16]
    ciphertext = decoded_ciphertext[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()
    return data.decode()

def securely_store_identifier(identifier, password, storage_path="hardware_id.enc"):
    """
    Securely stores a hardware identifier.

    Args:
        identifier: The hardware identifier string.
        password:  A password or passphrase used for encryption.  This should be securely obtained and managed (e.g., using Android Keystore).
        storage_path: The path to the encrypted file.
    """
    salt = generate_salt()
    key = derive_key(password, salt)
    ciphertext = encrypt_data(identifier, key)

    # Store salt and ciphertext securely.
    # This example stores salt and ciphertext separately for better security.
    salt_path = storage_path + ".salt"
    ciphertext_path = storage_path + ".enc"

    try:
        with open(salt_path, "wb") as f:
            f.write(base64.b64encode(salt))
        with open(ciphertext_path, "wb") as f:
            f.write(ciphertext)
    except Exception as e:
        print(f"Error during storage: {e}")


def securely_retrieve_identifier(password, storage_path="hardware_id.enc"):
    """
    Securely retrieves a hardware identifier.

    Args:
        password: The password or passphrase used for encryption.  Should be the same as the one used during storage.
        storage_path: The path to the encrypted file (base name).

    Returns:
        The hardware identifier string, or None if retrieval fails.
    """
    salt_path = storage_path + ".salt"
    ciphertext_path = storage_path + ".enc"

    try:
        with open(salt_path, "rb") as f:
            salt = base64.b64decode(f.read())
        with open(ciphertext_path, "rb") as f:
            ciphertext = f.read()

        key = derive_key(password, salt)
        identifier = decrypt_data(ciphertext, key)
        return identifier
    except FileNotFoundError:
        print("Error: Encrypted file or salt not found.")
        return None
    except Exception as e:
        print(f"Error during decryption: {e}")  # Log the specific error
        return None

if __name__ == '__main__':
    # Example Usage (Replace with appropriate Android-specific mechanisms)
    identifier_to_store = "unique_hardware_id_12345"  # Replace with the actual hardware ID
    encryption_password = "my_strong_password"  # Replace with a *strong*, securely stored password. DO NOT HARDCODE.
    storage_location = "hardware_id"  # File base name

    securely_store_identifier(identifier_to_store, encryption_password, storage_location)
    retrieved_identifier = securely_retrieve_identifier(encryption_password, storage_location)

    if retrieved_identifier:
        print(f"Retrieved Identifier: {retrieved_identifier}")
    else:
        print("Failed to retrieve identifier.")