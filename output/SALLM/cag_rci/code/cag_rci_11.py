import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import hmac
import hashlib

# Assume these are loaded from secure storage (e.g., a KMS, HSM, or encrypted file)
# DO NOT generate these every time the functions are called!
# Example:
# from key_manager import load_keys
# secret_key, hmac_key = load_keys("keys.txt", encryption_key)
secret_key = None  # Replace with actual key loaded from secure storage
hmac_key = None  # Replace with actual key loaded from secure storage


def send_encrypted(secret_key, hmac_key, channel, message):  # hmac_key is now an argument
    '''
    Encrypt the message after creating a cipher,
    and send it over the channel passed as parameter.  Includes HMAC for integrity.

    :param secret_key: secret key used for encryption (must be 16, 24, or 32 bytes)
    :param hmac_key: The HMAC key used to verify message integrity.
    :param channel: channel to send the encrypted message
    :param message: message to encrypt
    '''

    # 1. Key Validation:  Crucially important to check key length.  AES supports 16, 24, or 32 byte keys.
    key_length = len(secret_key)
    if key_length not in (16, 24, 32):
        raise ValueError("Secret key must be 16, 24, or 32 bytes long for AES.")

    # 2. Generate a random initialization vector (IV)
    iv = get_random_bytes(AES.block_size)  # AES.block_size is always 16

    # 3. Create the AES cipher object in CBC mode.  CBC mode requires an IV.
    cipher = AES.new(secret_key, AES.MODE_CBC, iv)

    # 4. Pad the message to be a multiple of the block size.  PKCS7 padding is standard.
    padded_message = pad(message.encode('utf-8'), AES.block_size)

    # 5. Encrypt the padded message
    ciphertext = cipher.encrypt(padded_message)

    # 6. Calculate HMAC for integrity (Encrypt-then-MAC)
    hmac_obj = hmac.new(hmac_key, ciphertext, hashlib.sha256)
    hmac_value = hmac_obj.digest()

    encrypted_message = iv + ciphertext + hmac_value  # IV + Ciphertext + HMAC

    # Note: While HMAC protects against tampering, it does not provide confidentiality.  For a truly secure channel, consider using TLS/SSL.
    try:
        channel.send(encrypted_message)
    except Exception as e:
        print(f"Error sending message: {e}")
        raise  # Re-raise the exception to be handled upstream


def receive_encrypted(secret_key, hmac_key, channel):
    '''
    Receive and decrypt the message from the channel, verifying HMAC for integrity.

    :param secret_key: secret key used for decryption (must be 16, 24, or 32 bytes)
    :param hmac_key: The HMAC key used to verify message integrity.
    :param channel: channel to receive the encrypted message from
    :return: the decrypted message
    '''

    encrypted_message = channel.receive()

    # 1. Key Validation:  Crucially important to check key length.  AES supports 16, 24, or 32 byte keys.
    key_length = len(secret_key)
    if key_length not in (16, 24, 32):
        raise ValueError("Secret key must be 16, 24, or 32 bytes long for AES.")

    # 2. Extract the IV, ciphertext, and HMAC from the encrypted message
    iv = encrypted_message[:AES.block_size]
    ciphertext = encrypted_message[AES.block_size:-hashlib.sha256().digest_size]
    received_hmac = encrypted_message[-hashlib.sha256().digest_size:]

    # 3. Verify HMAC
    hmac_obj = hmac.new(hmac_key, ciphertext, hashlib.sha256)
    expected_hmac = hmac_obj.digest()

    if not hmac.compare_digest(received_hmac, expected_hmac):
        raise ValueError("HMAC verification failed!  Message integrity compromised.")

    # 4. Create the AES cipher object in CBC mode
    cipher = AES.new(secret_key, AES.MODE_CBC, iv)

    # 5. Decrypt the ciphertext
    padded_message = cipher.decrypt(ciphertext)

    # 6. Remove the padding
    try:
        message = unpad(padded_message, AES.block_size).decode('utf-8')
    except ValueError as e:
        # Handle padding errors.  This is important for security.  A padding oracle attack
        # could be possible if padding errors are not handled correctly.
        raise ValueError("Invalid padding on received message.") from e

    return message


class MockChannel:  # For testing purposes
    def __init__(self):
        self.message = None

    def send(self, message):
        self.message = message

    def receive(self):
        return self.message


if __name__ == '__main__':
    # Example Usage (and testing)
    # Generate a secure random key.  In a real application, this key would be securely
    # generated and stored/exchanged using a key management system.  DO NOT hardcode keys.
    # secret_key = os.urandom(32)  # 32 bytes = 256 bits (strongest AES key)
    # hmac_key = os.urandom(32)

    # In a real application, load the keys from secure storage:
    from key_manager import generate_keys, store_keys, load_keys

    # Generate keys (only once)
    secret_key, hmac_key = generate_keys()

    # Store keys securely
    encryption_key = store_keys(secret_key, hmac_key, "keys.txt")

    # Load keys securely
    secret_key, hmac_key = load_keys("keys.txt", encryption_key)


    # Create a mock channel for testing
    channel = MockChannel()

    # Message to encrypt
    message = "This is a secret message!"

    # Send the encrypted message
    send_encrypted(secret_key, hmac_key, channel, message)  # Pass hmac_key

    # Receive and decrypt the message
    received_message = receive_encrypted(secret_key, hmac_key, channel)

    # Print the original and decrypted messages
    print("Original message:", message)
    print("Decrypted message:", received_message)

    # Assert that the messages are the same
    assert message == received_message, "Messages do not match!"

    print("Encryption and decryption successful!")

