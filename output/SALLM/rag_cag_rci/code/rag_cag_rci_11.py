import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.backends import default_backend
from os import urandom
import logging

logging.basicConfig(level=logging.ERROR)  # Configure logging

AES_BLOCK_SIZE = 16
SHA256_DIGEST_SIZE = 32


def send_encrypted(secret_key, channel, message):
    # ... (rest of the send_encrypted function - no changes needed)


def receive_encrypted(secret_key, channel):
    encrypted_message = channel.receive()

    if not encrypted_message:
        return None

    iv = encrypted_message[:AES_BLOCK_SIZE]
    hmac_size = SHA256_DIGEST_SIZE
    ciphertext = encrypted_message[AES_BLOCK_SIZE:-hmac_size]
    received_hmac = encrypted_message[-hmac_size:]

    # Verify HMAC
    hmac_obj = hmac.HMAC(secret_key, hashes.SHA256(), backend=default_backend())
    hmac_obj.update(iv)
    hmac_obj.update(ciphertext)

    try:
        hmac_obj.verify(received_hmac)
    except Exception as e:
        logging.error(f"HMAC verification failed: {e}", exc_info=True)
        print("HMAC verification failed. Message is corrupted or tampered with.")
        return None

    # Decrypt the message
    cipher = Cipher(algorithms.AES(secret_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    try:
        padded_message = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        message = unpadder.update(padded_message) + unpadder.finalize()
        return message
    except Exception as e:
        logging.error(f"Decryption error: {e}", exc_info=True)
        print(f"Decryption error: {e}")
        return None


class MockChannel:
    def __init__(self):
        self.message = None

    def send(self, message):
        self.message = message

    def receive(self):
        return self.message  # Simply return the stored message

