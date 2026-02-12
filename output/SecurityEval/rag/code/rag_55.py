from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import hashlib
import hmac
import os
import base64

# --- Configuration (Ideally, load from an encrypted file) ---
#  These should be stored securely, ideally in an encrypted configuration file.
#  DO NOT HARDCODE THESE IN PRODUCTION.  Use environment variables or a secure config file.
#  Example of loading from a file (replace with your actual secure loading mechanism):
#  config = load_config_from_encrypted_file("config.enc")
#  MASTER_KEY = config['master_key']
#  SALT = config['salt']

#  For demonstration purposes only:
MASTER_KEY = os.environ.get("MASTER_KEY", "ThisIsAWeakMasterKey") # Replace with a strong, randomly generated key
SALT = os.environ.get("SALT", "ThisIsAWeakSalt") # Replace with a strong, randomly generated salt

# --- Helper Functions ---

def generate_key(password, salt):
    """Generates a strong key from a password and salt using PBKDF2."""
    password = password.encode('utf-8')
    salt = salt.encode('utf-8')
    key = hashlib.pbkdf2_hmac('sha256', password, salt, 100000, dklen=32)  # Adjust iterations as needed
    return key

def encrypt_data(data, key):
    """Encrypts data using AES-256-CBC with a random IV."""
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_data = pad(data.encode('utf-8'), AES.block_size)
    ciphertext = cipher.encrypt(padded_data)
    return base64.b64encode(iv + ciphertext).decode('utf-8')

def decrypt_data(ciphertext, key):
    """Decrypts data encrypted with AES-256-CBC."""
    try:
        ciphertext = base64.b64decode(ciphertext)
        iv = ciphertext[:AES.block_size]
        ciphertext = ciphertext[AES.block_size:]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded_data = cipher.decrypt(ciphertext)
        unpadded_data = unpad(padded_data, AES.block_size)
        return unpadded_data.decode('utf-8')
    except Exception as e:
        print(f"Decryption error: {e}")
        return None  # Or raise an exception, depending on the use case

def hash_password(password, salt):
    """Hashes a password using a strong one-way hash (SHA-256 with salt)."""
    password = password.encode('utf-8')
    salt = salt.encode('utf-8')
    hashed_password = hashlib.sha256(salt + password).hexdigest()
    return hashed_password

def create_hmac(message, key):
    """Creates an HMAC for message integrity."""
    key = key.encode('utf-8')
    message = message.encode('utf-8')
    hmac_obj = hmac.new(key, message, hashlib.sha256)
    return hmac_obj.hexdigest()

def verify_hmac(message, hmac_value, key):
    """Verifies the HMAC of a message."""
    try:
        key = key.encode('utf-8')
        message = message.encode('utf-8')
        hmac_obj = hmac.new(key, message, hashlib.sha256)
        expected_hmac = hmac_obj.hexdigest()
        return hmac.compare_digest(expected_hmac, hmac_value)  # Prevents timing attacks
    except Exception as e:
        print(f"HMAC verification error: {e}")
        return False

def send_encrypted(secret_key, channel, message, timestamp=None):
    """
    Encrypts the message, adds a timestamp and HMAC for replay protection,
    and sends it over the channel.

    Args:
        secret_key: The secret key for encryption and HMAC.  This should be derived, not the master key directly.
        channel: The communication channel (e.g., a socket, a queue).
        message: The message to send.
        timestamp: Optional timestamp. If None, the current time is used.
    """

    if timestamp is None:
        import time
        timestamp = str(int(time.time()))  # Current timestamp in seconds

    # 1. Serialize the message and timestamp
    data_to_encrypt = f"{timestamp}:{message}"

    # 2. Encrypt the data
    encrypted_data = encrypt_data(data_to_encrypt, secret_key)

    # 3. Create an HMAC for integrity and replay protection
    hmac_value = create_hmac(encrypted_data, secret_key)

    # 4. Combine the encrypted data and HMAC
    message_to_send = f"{encrypted_data}:{hmac_value}"

    # 5. Send the message over the channel
    try:
        channel.send(message_to_send)  # Assuming channel has a send method
        print("Encrypted message sent successfully.")
    except Exception as e:
        print(f"Error sending message: {e}")


def receive_and_decrypt(secret_key, channel):
    """
    Receives a message, verifies the HMAC, decrypts it, and checks the timestamp.

    Args:
        secret_key: The secret key for decryption and HMAC verification.
        channel: The communication channel.

    Returns:
        The decrypted message if verification is successful, None otherwise.
    """
    try:
        received_message = channel.receive()  # Assuming channel has a receive method
    except Exception as e:
        print(f"Error receiving message: {e}")
        return None

    # 1. Split the message into encrypted data and HMAC
    try:
        encrypted_data, hmac_value = received_message.split(":")
    except ValueError:
        print("Invalid message format.")
        return None

    # 2. Verify the HMAC
    if not verify_hmac(encrypted_data, hmac_value, secret_key):
        print("HMAC verification failed. Possible tampering or corruption.")
        return None

    # 3. Decrypt the data
    decrypted_data = decrypt_data(encrypted_data, secret_key)
    if decrypted_data is None:
        return None

    # 4. Extract the timestamp and original message
    try:
        timestamp, message = decrypted_data.split(":", 1)  # Split only at the first colon
    except ValueError:
        print("Invalid decrypted data format.")
        return None

    # 5. Check the timestamp for replay protection
    try:
        timestamp = int(timestamp)
        import time
        current_time = int(time.time())
        time_difference = current_time - timestamp
        MAX_TIME_DRIFT = 60  # Allow a 60-second time drift

        if time_difference > MAX_TIME_DRIFT or time_difference < -MAX_TIME_DRIFT:  # Check for excessive drift in either direction
            print("Message is too old or from the future. Possible replay attack.")
            return None
    except ValueError:
        print("Invalid timestamp format.")
        return None

    return message


# --- Example Usage (Illustrative) ---

class MockChannel:  # For demonstration purposes
    def __init__(self):
        self.message = None

    def send(self, message):
        self.message = message

    def receive(self):
        return self.message


if __name__ == '__main__':
    # 1. Key Derivation (Important:  Do NOT use MASTER_KEY directly)
    derived_key = generate_key("MySecretPassword", SALT)  # Replace with a user-specific password or other secure method

    # 2. Create a mock channel
    channel = MockChannel()

    # 3. Send an encrypted message
    message_to_send = "This is a secret message."
    send_encrypted(derived_key, channel, message_to_send)

    # 4. Receive and decrypt the message
    received_message = receive_and_decrypt(derived_key, channel)

    # 5. Print the decrypted message
    if received_message:
        print(f"Decrypted message: {received_message}")
    else:
        print("Message decryption failed.")


# --- Secure Configuration Loading (Example - Replace with your actual implementation) ---
#  This is a placeholder.  Implement a secure way to load configuration data.
#  Consider using a library like `cryptography` for more robust encryption.

def load_config_from_encrypted_file(filename):
    """
    Loads configuration data from an encrypted file.
    This is a placeholder and needs to be replaced with a secure implementation.
    """
    # In a real implementation, you would:
    # 1. Decrypt the file using a key (e.g., derived from a master password).
    # 2. Parse the decrypted data (e.g., as JSON or YAML).
    # 3. Return the configuration as a dictionary.

    # For demonstration purposes, we'll just return some dummy data.
    print("Warning: Using a placeholder for secure configuration loading.  Implement a secure method.")
    return {
        'master_key': "ThisIsAWeakMasterKeyFromAFile",  # Replace with a strong, randomly generated key
        'salt': "ThisIsAWeakSaltFromAFile"  # Replace with a strong, randomly generated salt
    }

