from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import hashlib
import hmac
import os
import base64

# --- Configuration (Ideally, load from an encrypted file) ---
#  These should be stored securely, ideally in an encrypted configuration file
#  with restricted access.  Never hardcode these directly in the code.
#  For demonstration purposes, they are initialized here.  In a real application,
#  use a secure configuration management system.

# Example: Load from environment variables or a secure file.
# SECRET_KEY = os.environ.get("ENCRYPTION_KEY")
# HASH_SALT = os.environ.get("HASH_SALT")

# Generate a random secret key if one doesn't exist.  This is for demonstration only.
# In a real application, generate a strong key and store it securely.
if 'SECRET_KEY' not in locals():
    SECRET_KEY = get_random_bytes(32)  # 256-bit key
if 'HASH_SALT' not in locals():
    HASH_SALT = get_random_bytes(16)  # Random salt for password hashing

# --- End Configuration ---


def generate_key_from_password(password: str, salt: bytes) -> bytes:
    """
    Generates a secure key from a password using PBKDF2.

    Args:
        password: The password to derive the key from.
        salt: A random salt to add to the password.

    Returns:
        A secure key derived from the password.
    """
    kdf = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),  # Convert password to bytes
        salt,
        100000  # Number of iterations - adjust for security/performance
    )
    return kdf


def encrypt_data(data: bytes, key: bytes) -> bytes:
    """
    Encrypts data using AES-256 in CBC mode with a random IV.

    Args:
        data: The data to encrypt.
        key: The encryption key (must be 32 bytes for AES-256).

    Returns:
        The ciphertext (IV + encrypted data).
    """
    iv = get_random_bytes(AES.block_size)  # Initialization Vector
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(data, AES.block_size))
    return iv + ciphertext  # Prepend IV to the ciphertext


def decrypt_data(ciphertext: bytes, key: bytes) -> bytes:
    """
    Decrypts data encrypted with AES-256 in CBC mode.

    Args:
        ciphertext: The ciphertext (including the IV).
        key: The encryption key (must be 32 bytes for AES-256).

    Returns:
        The decrypted data.
    """
    iv = ciphertext[:AES.block_size]
    ciphertext = ciphertext[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return plaintext


def hash_password(password: str) -> tuple[str, str]:
    """Hashes a password using a strong one-way hash (SHA-256) with a salt.

    Args:
        password: The password to hash.

    Returns:
        A tuple containing the salt (base64 encoded) and the password hash (base64 encoded).
    """
    salt = get_random_bytes(16)
    hashed_password = hashlib.sha256(salt + password.encode('utf-8')).digest()
    return base64.b64encode(salt).decode('utf-8'), base64.b64encode(hashed_password).decode('utf-8')


def verify_password(password: str, stored_salt: str, stored_hash: str) -> bool:
    """Verifies a password against a stored hash and salt.

    Args:
        password: The password to verify.
        stored_salt: The base64 encoded salt used to hash the password.
        stored_hash: The base64 encoded stored password hash.

    Returns:
        True if the password matches the stored hash, False otherwise.
    """
    salt = base64.b64decode(stored_salt)
    hashed_password = hashlib.sha256(salt + password.encode('utf-8')).digest()
    return hmac.compare_digest(hashed_password, base64.b64decode(stored_hash))


def send_encrypted(secret_key: bytes, channel, message: str, timestamp: float = None):
    """
    Encrypts the message after creating a cipher, adds a timestamp and HMAC for replay protection,
    and sends it over the channel passed as parameter.

    :param secret_key: secret key used for encryption (must be 32 bytes for AES-256)
    :param channel: channel to send the encrypted message
    :param message: message to encrypt
    :param timestamp: Optional timestamp to include in the message for replay protection.  If None, the current time is used.
    """
    if not isinstance(secret_key, bytes) or len(secret_key) != 32:
        raise ValueError("Secret key must be a 32-byte bytes object (AES-256 key).")

    if timestamp is None:
        import time
        timestamp = time.time()

    # Convert message and timestamp to bytes
    message_bytes = message.encode('utf-8')
    timestamp_bytes = str(timestamp).encode('utf-8')

    # Concatenate message and timestamp
    data_to_encrypt = timestamp_bytes + b"||" + message_bytes  # Use a delimiter

    # Encrypt the data
    encrypted_data = encrypt_data(data_to_encrypt, secret_key)

    # Calculate HMAC for integrity and authentication
    hmac_obj = hmac.new(secret_key, encrypted_data, hashlib.sha256)
    hmac_value = hmac_obj.digest()

    # Combine encrypted data and HMAC
    message_to_send = hmac_value + encrypted_data

    # Send the combined message
    try:
        channel.send(message_to_send)  # Assuming channel has a send method
    except Exception as e:
        print(f"Error sending message: {e}")
        raise  # Re-raise the exception to signal failure


def receive_and_decrypt(secret_key: bytes, channel) -> str:
    """
    Receives an encrypted message from the channel, verifies the HMAC,
    and decrypts the message.

    :param secret_key: secret key used for decryption (must be 32 bytes for AES-256)
    :param channel: channel to receive the encrypted message from
    :return: The decrypted message, or None if verification fails.
    """
    if not isinstance(secret_key, bytes) or len(secret_key) != 32:
        raise ValueError("Secret key must be a 32-byte bytes object (AES-256 key).")

    try:
        received_message = channel.receive()  # Assuming channel has a receive method
    except Exception as e:
        print(f"Error receiving message: {e}")
        return None

    if len(received_message) < hashlib.sha256().digest_size:
        print("Message too short to contain HMAC.")
        return None

    # Separate HMAC and encrypted data
    received_hmac = received_message[:hashlib.sha256().digest_size]
    encrypted_data = received_message[hashlib.sha256().digest_size:]

    # Verify HMAC
    hmac_obj = hmac.new(secret_key, encrypted_data, hashlib.sha256)
    try:
        hmac.compare_digest(received_hmac, hmac_obj.digest())
    except:
        print("HMAC verification failed. Message may be tampered with.")
        return None

    # Decrypt the data
    try:
        decrypted_data = decrypt_data(encrypted_data, secret_key)
    except Exception as e:
        print(f"Decryption error: {e}")
        return None

    # Extract timestamp and message
    try:
        timestamp_bytes, message_bytes = decrypted_data.split(b"||", 1)
        timestamp = float(timestamp_bytes.decode('utf-8'))
        message = message_bytes.decode('utf-8')
    except ValueError:
        print("Invalid message format.")
        return None

    # Check for replay attack (optional, but highly recommended)
    import time
    current_time = time.time()
    if abs(current_time - timestamp) > 60:  # Allow a 60-second window
        print("Possible replay attack: Timestamp too old.")
        return None

    return message


# --- Example Usage (Illustrative) ---
if __name__ == '__main__':
    # Simulate a channel (replace with your actual channel implementation)
    class MockChannel:
        def __init__(self):
            self.message = None

        def send(self, message):
            self.message = message

        def receive(self):
            return self.message

    channel = MockChannel()

    # Example password handling
    password = "my_secret_password"
    salt, password_hash = hash_password(password)
    print(f"Salt: {salt}")
    print(f"Password Hash: {password_hash}")

    # Verify the password
    is_valid = verify_password(password, salt, password_hash)
    print(f"Password is valid: {is_valid}")

    # Example message encryption and sending
    message_to_send = "This is a secret message."
    try:
        send_encrypted(SECRET_KEY, channel, message_to_send)
        print("Message sent successfully.")
    except Exception as e:
        print(f"Failed to send message: {e}")

    # Example message receiving and decryption
    if channel.message:
        received_message = receive_and_decrypt(SECRET_KEY, channel)
        if received_message:
            print(f"Received message: {received_message}")
        else:
            print("Failed to receive or decrypt message.")
    else:
        print("No message received.")

