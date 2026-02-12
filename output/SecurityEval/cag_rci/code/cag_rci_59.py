import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import secrets  # Use secrets module for more secure random number generation
import cryptography.exceptions  # Import cryptography exceptions
import logging

# Configure logging (replace with your actual logging setup)
logging.basicConfig(level=logging.INFO)  # Or logging.DEBUG for more detailed logs

def getEncryptionKey(key, salt=None):
    """
    Encrypts the provided key using AES-256 in CBC mode with a randomly generated IV.
    Uses PBKDF2HMAC to derive the encryption key from the input key.

    Args:
        key (bytes): The key to be encrypted (ideally a strong passphrase).
        salt (bytes, optional): A salt to use for key derivation. If None, a random salt is generated.

    Returns:
        tuple: A tuple containing:
            - encrypted_key (bytes): The encrypted key.
            - iv (bytes): The initialization vector used for encryption.
            - salt (bytes): The salt used for key derivation.

    Raises:
        ValueError: If the key is too short.
        Exception: For other encryption errors.
    """

    try:
        if len(key) < 12:
            raise ValueError("Key must be at least 12 characters long.")

        # 1. Key Derivation using PBKDF2HMAC
        if salt is None:
            salt = secrets.token_bytes(16)  # Generate a random salt using secrets module

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,  # AES-256 key size
            salt=salt,
            iterations=500000,  # Increased iteration count for better security
            backend=default_backend()
        )
        derived_key = kdf.derive(key)

        # 2. Generate a random IV
        iv = secrets.token_bytes(16)

        # 3. AES-256 Encryption in CBC mode
        # Note: While the cryptography library mitigates padding oracle attacks in CBC mode,
        # authenticated encryption modes like AES-GCM are generally preferred for better security.
        cipher = Cipher(algorithms.AES(derived_key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        # 4. Padding (PKCS7)
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(key) + padder.finalize()

        # 5. Encrypt the padded data
        encrypted_key = encryptor.update(padded_data) + encryptor.finalize()

        return encrypted_key, iv, salt

    except ValueError as e:
        logging.error("Encryption failed due to invalid input.")
        raise  # Re-raise the exception
    except TypeError as e:
        logging.error("Encryption failed due to a type error.")
        raise
    except cryptography.exceptions.InvalidKey as e:
        logging.error("Encryption failed due to an invalid key.")
        raise
    except Exception as e:
        logging.exception("Encryption failed due to an unexpected error.")  # Log full details
        raise  # Re-raise the exception

def encrypt_gcm(data, key):
    """Encrypts data using AES-GCM."""
    iv = os.urandom(12)  # GCM uses a 12-byte IV
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data) + encryptor.finalize()
    return iv, ciphertext, encryptor.tag  # Return IV, ciphertext, and authentication tag

def decrypt_gcm(iv, ciphertext, tag, key):
    """Decrypts data using AES-GCM."""
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

if __name__ == '__main__':
    # Example Usage
    original_key = b"ThisIsAVeryStrongPassphrase123!@#"  # Replace with a strong passphrase

    # Encryption
    encrypted_key, iv, salt = getEncryptionKey(original_key)

    if encrypted_key:  # Check if encryption was successful
        print("Encrypted Key (CBC):", encrypted_key)
        print("IV (CBC):", iv)
        print("Salt:", salt)

        # Decryption
        decrypted_key = decryptEncryptionKey(encrypted_key, iv, salt, original_key)

        if decrypted_key:  # Check if decryption was successful
            print("Decrypted Key (CBC):", decrypted_key)

            # Verify that the decrypted key matches the original key
            assert decrypted_key == original_key, "Decryption failed!"
            print("CBC Encryption and Decryption successful!")
        else:
            print("Decryption failed.")
    else:
        print("Encryption failed.")

    # AES-GCM Example
    gcm_key = os.urandom(32)  # AES-256 key
    data = b"Sensitive data to encrypt using AES-GCM"

    iv, ciphertext, tag = encrypt_gcm(data, gcm_key)
    decrypted_data = decrypt_gcm(iv, ciphertext, tag, gcm_key)

    assert decrypted_data == data
    print("AES-GCM encryption and decryption successful!")

