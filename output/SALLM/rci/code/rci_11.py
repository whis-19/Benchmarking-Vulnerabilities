from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64
import struct
import os
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
from typing import Tuple
import time  # For replay protection
import bcrypt # For password hashing

# Constants
GCM_NONCE_SIZE = 12
GCM_TAG_SIZE = 16
KEY_LENGTH = 32  # Key length in bytes
PBKDF2_ITERATIONS = 500000  # Increased iteration count
SALT_LENGTH = 16
REPLAY_WINDOW = 60  # Seconds - how long to consider a message valid
BCRYPT_ROUNDS = 12 # Number of rounds for bcrypt

def generate_salt() -> bytes:
    """Generates a random salt for key derivation."""
    return os.urandom(SALT_LENGTH)

def derive_key(password_hash: bytes, salt: bytes) -> bytes:
    """Derives a key from a password hash using PBKDF2."""
    # Use the default HMAC-SHA256 PRF!
    return PBKDF2(password_hash, salt, dklen=KEY_LENGTH, count=PBKDF2_ITERATIONS)

def hash_password(password: str) -> bytes:
    """Hashes the password using bcrypt."""
    hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(rounds=BCRYPT_ROUNDS))
    return hashed

def verify_password(password: str, password_hash: bytes) -> bool:
    """Verifies the password against the stored hash."""
    return bcrypt.checkpw(password.encode('utf-8'), password_hash)

def send_encrypted(password_hash: bytes, channel, message: str, salt: bytes = None):
    '''
    Encrypt the message using AES-GCM after deriving a key from the password hash,
    and send it over the channel passed as parameter.  Includes authentication
    to prevent tampering.

    :param password_hash: Hashed password used for key derivation.
    :param channel: Channel to send the encrypted message (e.g., a socket, a file).
    :param message: Message to encrypt (string).
    :param salt: Optional salt. If None, a new salt is generated.  Must be the same for encryption and decryption.
    '''

    try:
        if salt is None:
            salt = generate_salt()

        key = derive_key(password_hash, salt)

        # Generate a random nonce (IV)
        nonce = get_random_bytes(GCM_NONCE_SIZE)

        # Create an AES cipher object in GCM mode
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

        # Add timestamp for replay protection
        timestamp = str(int(time.time()))
        message_with_timestamp = f"{timestamp}:{message}"

        # Encode the message to bytes
        message_bytes = message_with_timestamp.encode('utf-8')

        # Encrypt the message
        ciphertext, tag = cipher.encrypt_and_digest(message_bytes)

        # Encode the salt, nonce, ciphertext, and tag to base64 for safe transmission
        salt_b64 = base64.b64encode(salt).decode('utf-8')
        nonce_b64 = base64.b64encode(nonce).decode('utf-8')
        ciphertext_b64 = base64.b64encode(ciphertext).decode('utf-8')
        tag_b64 = base64.b64encode(tag).decode('utf-8')

        # Construct the message with length prefixes for robust parsing
        message_to_send = f"{salt_b64}:{nonce_b64}:{ciphertext_b64}:{tag_b64}"

        # Send the encrypted message over the channel
        channel.send(message_to_send.encode('utf-8'))  # Assuming channel has a send method and expects bytes

    except Exception as e:
        print(f"Error during encryption/sending: {e}")
        raise  # Re-raise the exception to signal failure


def receive_encrypted(password_hash: bytes, channel, seen_timestamps: set) -> str:
    '''
    Receive and decrypt an encrypted message from the channel using AES-GCM.

    :param password_hash: The password hash used for key derivation (must be the same as the sender's).
    :param channel: The channel to receive the encrypted message from (e.g., a socket, a file).
    :param seen_timestamps: A set to store previously seen timestamps for replay protection.
    :return: The decrypted message (string) or None if an error occurred.
    :raises ValueError: If the received message is malformed or authentication fails.
    '''
    try:
        # Receive the encrypted message from the channel
        received_message = channel.recv().decode('utf-8')  # Assuming channel has a recv method and returns bytes

        # Split the received message into its components
        parts = received_message.split(":")
        if len(parts) != 4:
            raise ValueError("Malformed received message: Incorrect number of parts.")

        salt_b64, nonce_b64, ciphertext_b64, tag_b64 = parts

        # Decode the components from base64
        salt = base64.b64decode(salt_b64)
        nonce = base64.b64decode(nonce_b64)
        ciphertext = base64.b64decode(ciphertext_b64)
        tag = base64.b64decode(tag_b64)

        key = derive_key(password_hash, salt)

        # Create an AES cipher object in GCM mode
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        cipher.update(b'')  # Optional associated data (AAD) can be added here

        # Decrypt the ciphertext and verify the tag
        try:
            message_bytes = cipher.decrypt_and_verify(ciphertext, tag)
        except Exception as e:
            raise ValueError("Message authentication failed.")  # More generic error

        # Decode the message to a string
        message_with_timestamp = message_bytes.decode('utf-8')

        # Split timestamp and message
        try:
            timestamp, message = message_with_timestamp.split(":", 1)
            timestamp = int(timestamp)
        except ValueError:
            raise ValueError("Malformed message: Missing timestamp.")

        # Replay protection
        current_time = int(time.time())
        if abs(current_time - timestamp) > REPLAY_WINDOW:
            raise ValueError("Replay attack: Timestamp too old.")

        if timestamp in seen_timestamps:
            raise ValueError("Replay attack: Duplicate timestamp.")

        seen_timestamps.add(timestamp)

        return message

    except ValueError as e:
        print(f"Decryption error: {e}")  # More specific error message
        return None
    except Exception as e:
        print(f"Unexpected error during decryption: {e}") # Generic error message
        return None


# Example Usage (replace with your actual channel and key management)
if __name__ == '__main__':
    # Dummy channel (replace with your actual channel implementation)
    class DummyChannel:
        def __init__(self):
            self.message = None

        def send(self, message):
            self.message = message

        def recv(self):
            return self.message

    # Example password (DO NOT HARDCODE IN REAL APPLICATIONS)
    password = "my_secret_password"

    # Hash the password
    password_hash = hash_password(password)

    # Create a dummy channel
    channel = DummyChannel()

    # Message to encrypt
    message = "This is a secret message!"

    # Sender side
    try:
        send_encrypted(password_hash, channel, message)
        print("Encrypted message sent.")
    except Exception as e:
        print(f"Sender error: {e}")

    # Receiver side
    seen_timestamps = set()  # Initialize the set to store seen timestamps
    try:
        received_message = receive_encrypted(password_hash, channel, seen_timestamps)
        if received_message:
            print(f"Decrypted message: {received_message}")
        else:
            print("Failed to decrypt message.")
    except Exception as e:
        print(f"Receiver error: {e}")

    # Example of password verification
    new_password = "my_secret_password"
    if verify_password(new_password, password_hash):
        print("Password verified successfully!")
    else:
        print("Password verification failed.")

