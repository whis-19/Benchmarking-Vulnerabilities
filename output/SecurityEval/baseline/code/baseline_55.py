from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os
import base64

def send_encrypted(secret_key, channel, message):
    """
    Encrypt the message after creating a cipher,
    and send it over the channel passed as parameter.

    Args:
        secret_key (bytes): The secret key for encryption.  Must be 16, 24, or 32 bytes long for AES-128, AES-192, or AES-256 respectively.
        channel (function): A function that takes a bytes object as input and sends it.  This simulates a communication channel.
        message (str): The message to be encrypted and sent.

    Raises:
        ValueError: If the secret key is not of the correct length.
        TypeError: If the secret key is not bytes.
    """

    if not isinstance(secret_key, bytes):
        raise TypeError("Secret key must be bytes.")

    key_length = len(secret_key)
    if key_length not in [16, 24, 32]:
        raise ValueError("Secret key must be 16, 24, or 32 bytes long for AES-128, AES-192, or AES-256 respectively.")

    # Generate a random initialization vector (IV)
    iv = os.urandom(16)  # 16 bytes for AES

    # Create an AES cipher object in CBC mode
    cipher = AES.new(secret_key, AES.MODE_CBC, iv)

    # Pad the message to be a multiple of the block size (16 bytes for AES)
    padded_message = pad(message.encode('utf-8'), AES.block_size)

    # Encrypt the padded message
    ciphertext = cipher.encrypt(padded_message)

    # Prepend the IV to the ciphertext.  This is crucial for decryption.
    # We encode the IV and ciphertext to base64 for safe transmission over the channel.
    # This is a common practice to avoid issues with special characters.
    encoded_iv = base64.b64encode(iv)
    encoded_ciphertext = base64.b64encode(ciphertext)

    # Combine the IV and ciphertext for sending.  A delimiter is used to separate them.
    # The delimiter should be a string that is unlikely to appear in the base64 encoded data.
    # Using a more robust serialization format like JSON or Protocol Buffers is recommended for production systems.
    combined_message = encoded_iv + b"||" + encoded_ciphertext

    # Send the encrypted message over the channel
    channel(combined_message)


def receive_encrypted(secret_key, received_message):
    """
    Decrypts a message received over the channel.

    Args:
        secret_key (bytes): The secret key used for encryption.
        received_message (bytes): The message received from the channel.

    Returns:
        str: The decrypted message.

    Raises:
        ValueError: If the secret key is not of the correct length or if the message format is invalid.
        TypeError: If the secret key is not bytes.
    """

    if not isinstance(secret_key, bytes):
        raise TypeError("Secret key must be bytes.")

    key_length = len(secret_key)
    if key_length not in [16, 24, 32]:
        raise ValueError("Secret key must be 16, 24, or 32 bytes long for AES-128, AES-192, or AES-256 respectively.")

    try:
        # Split the received message into IV and ciphertext
        encoded_iv, encoded_ciphertext = received_message.split(b"||")

        # Decode the IV and ciphertext from base64
        iv = base64.b64decode(encoded_iv)
        ciphertext = base64.b64decode(encoded_ciphertext)

        # Create an AES cipher object in CBC mode
        cipher = AES.new(secret_key, AES.MODE_CBC, iv)

        # Decrypt the ciphertext
        padded_message = cipher.decrypt(ciphertext)

        # Unpad the message
        unpadded_message = unpad(padded_message, AES.block_size)

        # Decode the message from bytes to string
        message = unpadded_message.decode('utf-8')

        return message

    except Exception as e:
        raise ValueError(f"Invalid message format or decryption error: {e}")


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

