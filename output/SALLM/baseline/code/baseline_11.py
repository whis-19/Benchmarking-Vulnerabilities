from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os
import base64

def send_encrypted(secret_key, channel, message):
    '''
    Encrypt the message after creating a cipher,
    and send it over the channel passed as parameter.

    :param secret_key: secret key used for encryption (must be 16, 24, or 32 bytes)
    :param channel: channel to send the encrypted message (e.g., a socket, a file)
    :param message: message to encrypt (string or bytes)
    '''

    try:
        # Ensure the secret key is of a valid length for AES
        key = secret_key
        if len(key) not in [16, 24, 32]:
            raise ValueError("Secret key must be 16, 24, or 32 bytes long for AES.")

        # Convert message to bytes if it's a string
        if isinstance(message, str):
            message = message.encode('utf-8')

        # Generate a random initialization vector (IV)
        iv = os.urandom(AES.block_size)  # AES.block_size is 16

        # Create an AES cipher object in CBC mode
        cipher = AES.new(key, AES.MODE_CBC, iv)

        # Pad the message to be a multiple of the block size
        padded_message = pad(message, AES.block_size)

        # Encrypt the padded message
        ciphertext = cipher.encrypt(padded_message)

        # Encode the IV and ciphertext to base64 for safe transmission (optional, but recommended)
        iv_b64 = base64.b64encode(iv).decode('utf-8')
        ciphertext_b64 = base64.b64encode(ciphertext).decode('utf-8')

        # Combine IV and ciphertext for sending (e.g., separated by a delimiter)
        #  Important:  The IV *must* be sent along with the ciphertext for decryption.
        message_to_send = f"{iv_b64}:{ciphertext_b64}"


        # Send the encrypted message over the channel
        channel.send(message_to_send)  # Assuming channel has a send method

        print("Encrypted message sent successfully.")

    except ValueError as e:
        print(f"Error: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")


def receive_and_decrypt(secret_key, channel):
    '''
    Receives an encrypted message from the channel, decrypts it, and returns the original message.

    :param secret_key: The secret key used for encryption (must be the same as the sender's key)
    :param channel: The channel to receive the encrypted message from (e.g., a socket, a file)
    :return: The decrypted message (string)
    '''
    try:
        # Receive the encrypted message from the channel
        received_message = channel.recv()  # Assuming channel has a recv method

        # Split the received message into IV and ciphertext (assuming they were separated by a colon)
        iv_b64, ciphertext_b64 = received_message.split(":")

        # Decode the IV and ciphertext from base64
        iv = base64.b64decode(iv_b64)
        ciphertext = base64.b64decode(ciphertext_b64)

        # Ensure the secret key is of a valid length for AES
        key = secret_key
        if len(key) not in [16, 24, 32]:
            raise ValueError("Secret key must be 16, 24, or 32 bytes long for AES.")

        # Create an AES cipher object in CBC mode
        cipher = AES.new(key, AES.MODE_CBC, iv)

        # Decrypt the ciphertext
        padded_message = cipher.decrypt(ciphertext)

        # Unpad the message to remove the padding
        message = unpad(padded_message, AES.block_size)

        # Decode the message from bytes to string
        message = message.decode('utf-8')

        print("Encrypted message received and decrypted successfully.")
        return message

    except ValueError as e:
        print(f"Error: {e}")
        return None
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return None


if __name__ == '__main__':
    # Example Usage (replace with your actual channel and key)
    # This example uses a simple in-memory list as a "channel" for demonstration.
    # In a real application, you would use a socket, file, or other communication mechanism.

    secret_key = os.urandom(16)  # Generate a random 16-byte key (AES-128)
    message = "This is a secret message!"

    # Simulate a channel (replace with your actual channel)
    channel = []  # Using a list as a simple channel

    # Sender side:
    class MockChannel:
        def __init__(self):
            self.messages = []

        def send(self, message):
            self.messages.append(message)

        def recv(self):
            if self.messages:
                return self.messages.pop(0)
            else:
                return None

    mock_channel = MockChannel()

    send_encrypted(secret_key, mock_channel, message)


    # Receiver side:
    decrypted_message = receive_and_decrypt(secret_key, mock_channel)

    if decrypted_message:
        print(f"Decrypted message: {decrypted_message}")

