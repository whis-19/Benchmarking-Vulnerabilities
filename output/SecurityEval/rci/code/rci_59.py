import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hmac, hashes
import secrets
from cryptography.hazmat.primitives import kdf
from cryptography.exceptions import InvalidSignature

def encryptKey(key: bytes, persistent_key: bytes) -> tuple[bytes, bytes]:
    """
    Encrypts the provided key using AES in CBC mode with a randomly generated IV and a persistent key.
    Includes HMAC for authentication.  Uses HKDF to derive separate encryption and HMAC keys.

    Args:
        key: The key to encrypt (bytes).
        persistent_key: A persistent, pre-shared key (bytes) used for key derivation.

    Returns:
        A tuple containing:
            - The IV (bytes).
            - The ciphertext (bytes + HMAC).

    Raises:
        TypeError: If the input key or persistent_key is not a bytes object.
        ValueError: If the key or persistent_key is empty.
    """

    if not isinstance(key, bytes) or not isinstance(persistent_key, bytes):
        raise TypeError("Key and persistent_key must be bytes objects.")

    if not key or not persistent_key:
        raise ValueError("Key and persistent_key cannot be empty.")

    # Generate a random IV (Initialization Vector)
    iv = os.urandom(16)  # 128-bit IV

    # Derive separate encryption and HMAC keys using HKDF
    hkdf = kdf.HKDF(
        algorithm=hashes.SHA256(),
        length=64,  # 32 bytes for AES key + 32 bytes for HMAC key
        salt=None,  # No salt for simplicity (consider adding one)
        info=b"encryption_and_hmac_keys",  # Contextual information
        backend=default_backend()
    )
    derived_keys = hkdf.derive(persistent_key)
    encryption_key = derived_keys[:32]
    hmac_key = derived_keys[32:]

    # Create an AES cipher object in CBC mode
    cipher = Cipher(algorithms.AES(encryption_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Pad the key to be a multiple of the block size (16 bytes for AES)
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_key = padder.update(key) + padder.finalize()

    # Encrypt the padded key
    ciphertext = encryptor.update(padded_key) + encryptor.finalize()

    # Calculate HMAC
    h = hmac.HMAC(hmac_key, hashes.SHA256(), backend=default_backend())
    h.update(iv + ciphertext)
    hmac_tag = h.finalize()

    return iv, ciphertext + hmac_tag


def decryptKey(iv: bytes, ciphertext: bytes, persistent_key: bytes) -> bytes:
    """
    Decrypts the encrypted key using AES in CBC mode and verifies HMAC.

    Args:
        iv: The Initialization Vector (IV) used for encryption.
        ciphertext: The encrypted key (ciphertext + HMAC).
        persistent_key: The persistent key used for key derivation.

    Returns:
        The decrypted key (bytes).

    Raises:
        ValueError: If the ciphertext is too short (less than HMAC length) or if HMAC verification fails.
    """

    if len(ciphertext) < 32:  # HMAC-SHA256 is 32 bytes
        raise ValueError("Ciphertext is too short (HMAC missing).")

    hmac_tag = ciphertext[-32:]
    ciphertext_without_hmac = ciphertext[:-32]

    # Derive separate encryption and HMAC keys using HKDF
    hkdf = kdf.HKDF(
        algorithm=hashes.SHA256(),
        length=64,  # 32 bytes for AES key + 32 bytes for HMAC key
        salt=None,  # No salt for simplicity (consider adding one)
        info=b"encryption_and_hmac_keys",  # Contextual information
        backend=default_backend()
    )
    derived_keys = hkdf.derive(persistent_key)
    encryption_key = derived_keys[:32]
    hmac_key = derived_keys[32:]


    # Verify HMAC
    h = hmac.HMAC(hmac_key, hashes.SHA256(), backend=default_backend())
    h.update(iv + ciphertext_without_hmac)
    try:
        h.verify(hmac_tag)
    except InvalidSignature:
        raise ValueError("HMAC verification failed.")

    # Create an AES cipher object in CBC mode
    cipher = Cipher(algorithms.AES(encryption_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    # Decrypt the ciphertext
    padded_key = decryptor.update(ciphertext_without_hmac) + decryptor.finalize()

    # Remove the padding
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    key = unpadder.update(padded_key) + unpadder.finalize()

    return key


if __name__ == '__main__':
    # Example usage:
    original_key = b"This is a secret key that needs encryption"  # Must be bytes
    print(f"Original Key: {original_key}")

    # Generate or retrieve a persistent key (store this securely!)
    persistent_key = secrets.token_bytes(32)  # 256-bit key.  Use secrets for crypto-strength randomness.
    #print(f"Persistent Key: {persistent_key.hex()}") # NEVER do this in production.  Just for demonstration.
    #  Instead of printing, store the persistent_key securely!

    # Encrypt the key
    iv, ciphertext = encryptKey(original_key, persistent_key)
    print(f"Encrypted Key: {ciphertext.hex()}")

    # Decrypt the key
    decrypted_key = decryptKey(iv, ciphertext, persistent_key)
    print(f"Decrypted Key: {decrypted_key}")

    # Verify that the decrypted key matches the original key
    if decrypted_key == original_key:
        print("Encryption and decryption successful!")
    else:
        print("Encryption and decryption failed.")

