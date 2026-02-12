import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

def getEncryptionKey(key: bytes) -> bytes:
    """
    Encrypts the provided key using AES in CBC mode with a randomly generated IV.

    Args:
        key: The key to encrypt (bytes).  It's crucial this is a bytes object.

    Returns:
        A bytes object containing the IV prepended to the ciphertext.

    Raises:
        TypeError: If the input key is not a bytes object.
        ValueError: If the key is empty.
    """

    if not isinstance(key, bytes):
        raise TypeError("Key must be a bytes object.")

    if not key:
        raise ValueError("Key cannot be empty.")

    # Generate a random encryption key (AES key)
    encryption_key = os.urandom(32)  # 256-bit key

    # Generate a random IV (Initialization Vector)
    iv = os.urandom(16)  # 128-bit IV

    # Create an AES cipher object in CBC mode
    cipher = Cipher(algorithms.AES(encryption_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Pad the key to be a multiple of the block size (16 bytes for AES)
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_key = padder.update(key) + padder.finalize()

    # Encrypt the padded key
    ciphertext = encryptor.update(padded_key) + encryptor.finalize()

    # Prepend the IV to the ciphertext for decryption later
    return iv + ciphertext


def decryptEncryptionKey(encrypted_key: bytes, encryption_key: bytes) -> bytes:
    """
    Decrypts the encrypted key using AES in CBC mode.

    Args:
        encrypted_key: The encrypted key (IV + ciphertext).
        encryption_key: The AES key used for encryption.

    Returns:
        The decrypted key (bytes).

    Raises:
        ValueError: If the encrypted key is too short (less than IV length).
    """

    if len(encrypted_key) < 16:  # IV length is 16 bytes
        raise ValueError("Encrypted key is too short.")

    iv = encrypted_key[:16]
    ciphertext = encrypted_key[16:]

    # Create an AES cipher object in CBC mode
    cipher = Cipher(algorithms.AES(encryption_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    # Decrypt the ciphertext
    padded_key = decryptor.update(ciphertext) + decryptor.finalize()

    # Remove the padding
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    key = unpadder.update(padded_key) + unpadder.finalize()

    return key


if __name__ == '__main__':
    # Example usage:
    original_key = b"This is a secret key that needs encryption"  # Must be bytes
    print(f"Original Key: {original_key}")

    # Generate a random AES key for encryption
    aes_key = os.urandom(32)

    # Encrypt the key
    encrypted_key = getEncryptionKey(original_key)
    print(f"Encrypted Key: {encrypted_key.hex()}")

    # Decrypt the key
    decrypted_key = decryptEncryptionKey(encrypted_key, aes_key)
    print(f"Decrypted Key: {decrypted_key}")

    # Verify that the decrypted key matches the original key
    if decrypted_key == original_key:
        print("Encryption and decryption successful!")
    else:
        print("Encryption and decryption failed.")

