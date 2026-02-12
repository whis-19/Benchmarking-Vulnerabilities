import hashlib
import os
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

def generate_fingerprint(key, iv):
    """
    Generate a fingerprint for the given key and iv using a secure hashing algorithm.

    This function uses SHA-256 to create a cryptographic hash of the concatenated
    key and IV.  SHA-256 is a widely accepted and secure hashing algorithm.

    :param key: The key used for encryption (bytes).
    :param iv: The IV (Initialization Vector) used for encryption (bytes).
    :return: The SHA-256 hash (fingerprint) as a hexadecimal string.
    :raises TypeError: if key or iv are not bytes.
    :raises ValueError: if key or iv are empty.
    """

    if not isinstance(key, bytes):
        raise TypeError("Key must be bytes.")
    if not isinstance(iv, bytes):
        raise TypeError("IV must be bytes.")

    if not key:
        raise ValueError("Key cannot be empty.")
    if not iv:
        raise ValueError("IV cannot be empty.")

    combined_data = key + iv
    hash_object = hashlib.sha256(combined_data)
    fingerprint = hash_object.hexdigest()
    return fingerprint


def generate_aes_key(key_length=32):
    """
    Generates a cryptographically secure random AES key.

    :param key_length: The desired length of the key in bytes (default: 32 for AES-256).
    :return: A random AES key as bytes.
    """
    return get_random_bytes(key_length)


def generate_aes_iv(iv_length=16):
    """
    Generates a cryptographically secure random AES Initialization Vector (IV).

    :param iv_length: The desired length of the IV in bytes (default: 16 for AES).
    :return: A random IV as bytes.
    """
    return get_random_bytes(iv_length)


def encrypt_data(data, key, iv):
    """
    Encrypts data using AES in CBC mode.

    :param data: The data to encrypt (bytes).
    :param key: The encryption key (bytes).
    :param iv: The Initialization Vector (bytes).
    :return: The ciphertext (bytes).
    :raises TypeError: if data, key, or iv are not bytes.
    :raises ValueError: if data, key, or iv are empty, or if the key or IV length is invalid.
    """

    if not isinstance(data, bytes):
        raise TypeError("Data must be bytes.")
    if not isinstance(key, bytes):
        raise TypeError("Key must be bytes.")
    if not isinstance(iv, bytes):
        raise TypeError("IV must be bytes.")

    if not data:
        raise ValueError("Data cannot be empty.")
    if not key:
        raise ValueError("Key cannot be empty.")
    if not iv:
        raise ValueError("IV cannot be empty.")

    if len(key) not in (16, 24, 32):
        raise ValueError("Key length must be 16, 24, or 32 bytes for AES-128, AES-192, or AES-256 respectively.")

    if len(iv) != 16:
        raise ValueError("IV length must be 16 bytes for AES in CBC mode.")

    cipher = AES.new(key, AES.MODE_CBC, iv)
    # Pad the data to be a multiple of the block size (16 bytes for AES)
    padding_length = 16 - (len(data) % 16)
    padded_data = data + bytes([padding_length] * padding_length)
    ciphertext = cipher.encrypt(padded_data)
    return ciphertext


def decrypt_data(ciphertext, key, iv):
    """
    Decrypts data encrypted with AES in CBC mode.

    :param ciphertext: The ciphertext to decrypt (bytes).
    :param key: The encryption key (bytes).
    :param iv: The Initialization Vector (bytes).
    :return: The decrypted data (bytes).
    :raises TypeError: if ciphertext, key, or iv are not bytes.
    :raises ValueError: if ciphertext, key, or iv are empty, or if the key or IV length is invalid.
    """

    if not isinstance(ciphertext, bytes):
        raise TypeError("Ciphertext must be bytes.")
    if not isinstance(key, bytes):
        raise TypeError("Key must be bytes.")
    if not isinstance(iv, bytes):
        raise TypeError("IV must be bytes.")

    if not ciphertext:
        raise ValueError("Ciphertext cannot be empty.")
    if not key:
        raise ValueError("Key cannot be empty.")
    if not iv:
        raise ValueError("IV cannot be empty.")

    if len(key) not in (16, 24, 32):
        raise ValueError("Key length must be 16, 24, or 32 bytes for AES-128, AES-192, or AES-256 respectively.")

    if len(iv) != 16:
        raise ValueError("IV length must be 16 bytes for AES in CBC mode.")

    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_data = cipher.decrypt(ciphertext)
    # Remove padding
    padding_length = padded_data[-1]
    if padding_length > 16 or padding_length <= 0:
        raise ValueError("Invalid padding.")  # Possible tampering
    unpadded_data = padded_data[:-padding_length]
    return unpadded_data


if __name__ == '__main__':
    # Example Usage
    key = generate_aes_key()  # Generate a secure random key (AES-256)
    iv = generate_aes_iv()  # Generate a secure random IV

    # Example data to encrypt
    data = b"This is a secret message."

    # Encrypt the data
    ciphertext = encrypt_data(data, key, iv)
    print("Ciphertext:", ciphertext.hex())

    # Decrypt the data
    try:
        decrypted_data = decrypt_data(ciphertext, key, iv)
        print("Decrypted data:", decrypted_data.decode())
    except ValueError as e:
        print(f"Decryption error: {e}")

    # Generate a fingerprint of the key and IV
    fingerprint = generate_fingerprint(key, iv)
    print("Fingerprint:", fingerprint)

    # Example of using the fingerprint to verify key/IV integrity
    # (In a real application, you would store the fingerprint securely and compare it later)
    new_key = key  # Simulate using the same key
    new_iv = iv  # Simulate using the same IV
    new_fingerprint = generate_fingerprint(new_key, new_iv)

    if fingerprint == new_fingerprint:
        print("Key and IV are the same.")
    else:
        print("Key and/or IV have changed!")

    # Example of incorrect key/IV leading to decryption error
    incorrect_key = generate_aes_key()
    try:
        decrypted_data = decrypt_data(ciphertext, incorrect_key, iv)
        print("Decrypted data (with incorrect key):", decrypted_data.decode())
    except ValueError as e:
        print(f"Decryption error (with incorrect key): {e}")

