import os
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidTag
import base64

def generate_salt():
    """Generates a cryptographically secure random salt."""
    return os.urandom(16)

def hash_password(password, salt):
    """Hashes the password using SHA-256 with a salt."""
    salted_password = salt + password.encode('utf-8')
    hashed_password = hashlib.sha256(salted_password).hexdigest()
    return hashed_password

def getEncryptionKey(key, encryption_key, salt):
    """
    Encrypts the key using AES-CBC with a provided encryption key and salt.

    Args:
        key (str): The key to encrypt.
        encryption_key (bytes): The encryption key (must be 32 bytes for AES-256).  This should be securely stored and managed.
        salt (bytes): A unique salt for this encryption operation.

    Returns:
        str: The base64 encoded ciphertext.
    """

    if not isinstance(encryption_key, bytes) or len(encryption_key) != 32:
        raise ValueError("Encryption key must be a 32-byte bytes object (AES-256 key).")

    iv = os.urandom(16)  # Initialization Vector
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(key.encode('utf-8')) + padder.finalize()

    cipher = Cipher(algorithms.AES(encryption_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    # Store the IV and salt along with the ciphertext (e.g., prepended).  Crucial for decryption.
    # Using a simple concatenation for demonstration; consider a more robust serialization format.
    combined_data = salt + iv + ciphertext
    return base64.b64encode(combined_data).decode('utf-8')


def decrypt_key(encrypted_key, encryption_key):
    """
    Decrypts the key using AES-CBC.

    Args:
        encrypted_key (str): The base64 encoded ciphertext.
        encryption_key (bytes): The encryption key used for encryption.

    Returns:
        str: The decrypted key.
    """
    if not isinstance(encryption_key, bytes) or len(encryption_key) != 32:
        raise ValueError("Encryption key must be a 32-byte bytes object (AES-256 key).")

    try:
        combined_data = base64.b64decode(encrypted_key)
        salt = combined_data[:16]
        iv = combined_data[16:32]
        ciphertext = combined_data[32:]

        cipher = Cipher(algorithms.AES(encryption_key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_padded_data = decryptor.update(ciphertext) + decryptor.finalize()

        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()

        return decrypted_data.decode('utf-8')

    except Exception as e:
        print(f"Decryption error: {e}")
        return None  # Or raise an exception, depending on the desired behavior


# Example Usage (Illustrative - DO NOT HARDCODE KEYS IN REAL APPLICATIONS)
if __name__ == '__main__':
    #  In a real application, the encryption key should be:
    #  1. Generated securely (e.g., using os.urandom(32)).
    #  2. Stored securely (e.g., in a hardware security module, encrypted configuration file, or key management system).
    #  3. Rotated regularly.
    encryption_key = os.urandom(32)  # Replace with secure key generation and storage
    key_to_encrypt = "my_secret_key"
    salt = generate_salt()

    encrypted_key = getEncryptionKey(key_to_encrypt, encryption_key, salt)
    print(f"Encrypted key: {encrypted_key}")

    decrypted_key = decrypt_key(encrypted_key, encryption_key)
    print(f"Decrypted key: {decrypted_key}")

    # Password hashing example
    password = "my_password"
    salt = generate_salt()
    hashed_password = hash_password(password, salt)
    print(f"Hashed password: {hashed_password}")

    # Verification example (compare the hash of the entered password with the stored hash)
    entered_password = "my_password"
    hashed_entered_password = hash_password(entered_password, salt)

    if hashed_entered_password == hashed_password:
        print("Passwords match!")
    else:
        print("Passwords do not match!")

