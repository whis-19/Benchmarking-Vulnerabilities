import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import hmac
import hashlib

def send_encrypted(secret_key, channel, message):
    '''
    Encrypt the message after creating a cipher,
    and send it over the channel passed as parameter.

    :param secret_key: secret key used for encryption (must be bytes)
    :param channel: channel to send the encrypted message
    :param message: message to encrypt (must be bytes)
    '''

    # 1. Use strong, modern cryptographic algorithms: AES-256 in CBC mode
    # 2. Never implement custom cryptography: Using PyCryptodome library

    # Generate a random initialization vector (IV)
    iv = get_random_bytes(AES.block_size)

    # Create a cipher object
    cipher = AES.new(secret_key, AES.MODE_CBC, iv)

    # Pad the message to be a multiple of the block size
    padded_message = pad(message, AES.block_size)

    # Encrypt the message
    ciphertext = cipher.encrypt(padded_message)

    # Create an HMAC for integrity and authentication
    hmac_obj = hmac.new(secret_key, digestmod=hashlib.sha256)
    hmac_obj.update(iv)
    hmac_obj.update(ciphertext)
    hmac_value = hmac_obj.digest()

    # Combine IV, ciphertext, and HMAC for transmission
    # Include the IV to decrypt the message
    # Include the HMAC to verify the integrity and authenticity of the message
    encrypted_message = iv + ciphertext + hmac_value

    # Send the encrypted message over the channel
    channel.send(encrypted_message)


def receive_encrypted(secret_key, channel):
    '''
    Receive and decrypt the message from the channel.

    :param secret_key: secret key used for decryption (must be bytes)
    :param channel: channel to receive the encrypted message from
    :return: decrypted message (bytes) or None if decryption fails
    '''

    encrypted_message = channel.receive()

    if not encrypted_message:
        return None

    # Extract IV, ciphertext, and HMAC
    iv = encrypted_message[:AES.block_size]
    hmac_size = hashlib.sha256().digest_size
    ciphertext = encrypted_message[AES.block_size:-hmac_size]
    received_hmac = encrypted_message[-hmac_size:]

    # Verify HMAC
    hmac_obj = hmac.new(secret_key, digestmod=hashlib.sha256)
    hmac_obj.update(iv)
    hmac_obj.update(ciphertext)
    expected_hmac = hmac_obj.digest()

    if not hmac.compare_digest(received_hmac, expected_hmac):
        print("HMAC verification failed. Message is corrupted or tampered with.")
        return None

    # Create a cipher object
    cipher = AES.new(secret_key, AES.MODE_CBC, iv)

    # Decrypt the message
    try:
        padded_message = cipher.decrypt(ciphertext)
        # Unpad the message
        message = unpad(padded_message, AES.block_size)
        return message
    except ValueError as e:
        print(f"Decryption error: {e}")
        return None


class Channel:  # Example channel for demonstration
    def __init__(self):
        self.message = None

    def send(self, message):
        self.message = message

    def receive(self):
        return self.message


if __name__ == '__main__':
    # Example usage:
    # 3. Use proper key management and storage:  In a real application,
    #    the secret key should be securely generated, stored, and managed.
    #    This example uses a randomly generated key for demonstration purposes only.
    secret_key = get_random_bytes(32)  # AES-256 requires 32-byte key

    # Create a channel
    channel = Channel()

    # Message to be sent
    message = b"This is a secret message."

    # Send the encrypted message
    send_encrypted(secret_key, channel, message)

    # Receive and decrypt the message
    received_message = receive_encrypted(secret_key, channel)

    if received_message:
        print("Original message:", message.decode())
        print("Decrypted message:", received_message.decode())
    else:
        print("Message reception or decryption failed.")

