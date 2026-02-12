from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os
import base64
import json
import hmac
import hashlib

def send_encrypted(secret_key, channel, message):
    """
    Encrypts a message using AES-CBC with a random IV and PKCS7 padding, and adds an HMAC for authentication.
    The IV, ciphertext, and HMAC are encoded using base64 and combined into a JSON object
    for transmission.

    Args:
        secret_key (bytes): The secret key for encryption and HMAC.
        channel (function): A function that takes a bytes object as input and sends it.
        message (str): The message to be encrypted and sent.

    Raises:
        ValueError: If the secret key is not of the correct length.
        TypeError: If the secret key is not bytes.
        Exception: If any error occurs during encryption.
    """

    if not isinstance(secret_key, bytes):
        raise TypeError("Secret key must be bytes.")

    key_length = len(secret_key)
    if key_length not in [16, 24, 32]:
        raise ValueError("Secret key must be 16, 24, or 32 bytes long for AES-128, AES-192, or AES-256 respectively.")

    try:
        # Generate a random initialization vector (IV)
        iv = os.urandom(16)  # 16 bytes for AES

        # Create an AES cipher object in CBC mode
        cipher = AES.new(secret_key, AES.MODE_CBC, iv)

        # Pad the message to be a multiple of the block size (16 bytes for AES)
        padded_message = pad(message.encode('utf-8'), AES.block_size)

        # Encrypt the padded message
        ciphertext = cipher.encrypt(padded_message)

        # Calculate HMAC
        hmac_obj = hmac.new(secret_key, iv + ciphertext, hashlib.sha256)
        hmac_digest = hmac_obj.digest()

        # Encode the IV, ciphertext, and HMAC to base64 for safe transmission over the channel.
        encoded_iv = base64.b64encode(iv).decode('utf-8')
        encoded_ciphertext = base64.b64encode(ciphertext).decode('utf-8')
        encoded_hmac = base64.b64encode(hmac_digest).decode('utf-8')

        # Combine the IV, ciphertext, and HMAC into a JSON object
        data = {
            'iv': encoded_iv,
            'ciphertext': encoded_ciphertext,
            'hmac': encoded_hmac
        }
        combined_message = json.dumps(data).encode('utf-8')

        # Send the encrypted message over the channel
        channel(combined_message)

    except Exception as e:
        raise Exception(f"Encryption error: {e}")


def receive_encrypted(secret_key, received_message):
    """
    Decrypts a message received over the channel.  The message is expected to be a
    JSON object containing the base64 encoded IV, ciphertext, and HMAC.

    Args:
        secret_key (bytes): The secret key used for encryption.
        received_message (bytes): The message received from the channel.

    Returns:
        str: The decrypted message.

    Raises:
        ValueError: If the secret key is not of the correct length or if the message format is invalid or if the HMAC is invalid.
        TypeError: If the secret key is not bytes.
        Exception: If any error occurs during decryption.
    """

    if not isinstance(secret_key, bytes):
        raise TypeError("Secret key must be bytes.")

    key_length = len(secret_key)
    if key_length not in [16, 24, 32]:
        raise ValueError("Secret key must be 16, 24, or 32 bytes long for AES-128, AES-192, or AES-256 respectively.")

    try:
        # Decode the JSON object
        try:
            data = json.loads(received_message.decode('utf-8'))
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON format: {e}")

        # Extract the IV, ciphertext, and HMAC from the JSON object
        try:
            encoded_iv = data['iv']
            encoded_ciphertext = data['ciphertext']
            encoded_hmac = data['hmac']
        except KeyError as e:
            raise ValueError(f"Missing required field: {e}")

        # Decode the IV, ciphertext, and HMAC from base64
        try:
            iv = base64.b64decode(encoded_iv)
            ciphertext = base64.b64decode(encoded_ciphertext)
            hmac_digest = base64.b64decode(encoded_hmac)
        except base64.binascii.Error as e:
            raise ValueError(f"Invalid base64 encoding: {e}")

        # Verify HMAC
        hmac_obj = hmac.new(secret_key, iv + ciphertext, hashlib.sha256)
        expected_hmac = hmac_obj.digest()

        if not hmac.compare_digest(hmac_digest, expected_hmac):
            raise ValueError("Invalid HMAC: Message authentication failed.")


        # Create an AES cipher object in CBC mode
        cipher = AES.new(secret_key, AES.MODE_CBC, iv)

        # Decrypt the ciphertext
        padded_message = cipher.decrypt(ciphertext)

        # Unpad the message
        unpadded_message = unpad(padded_message, AES.block_size)

        # Decode the message from bytes to string
        message = unpadded_message.decode('utf-8')

        return message

    except ValueError as e:
        raise ValueError(f"Decryption error: {e}")
    except Exception as e:
        raise Exception(f"Decryption error: {e}")


if __name__ == '__main__':
    # Example usage:

    # Generate a random secret key (AES-256 in this example)
    secret_key = os.urandom(32)

    # Define a dummy channel (replace with your actual communication mechanism)
    def dummy_channel(message):
        print(f"Sending encrypted message: {message}")
        global received_message
        received_message = message

    # Message to be sent
    message = "This is a secret message!"

    # Encrypt and send the message
    received_message = None # Initialize received_message
    send_encrypted(secret_key, dummy_channel, message)

    # Receive and decrypt the message
    decrypted_message = receive_encrypted(secret_key, received_message)

    # Print the decrypted message
    print(f"Decrypted message: {decrypted_message}")

