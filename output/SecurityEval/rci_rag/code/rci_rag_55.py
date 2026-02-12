from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import hashlib
import hmac
import os
import secrets  # For generating cryptographically secure random numbers

# --- Security Considerations Addressed ---
# 1. & 2. Sensitive information handling: Encryption with AES and secure key management.
# 3. Channel security:  Assumes the 'channel' provides some level of transport security (e.g., TLS/SSL).  If not, further encryption/authentication is needed at the transport layer. TLS/SSL is the recommended solution. Without TLS/SSL, the entire encryption scheme is vulnerable to interception and attacks.
# 4. Authentication:  HMAC is used to authenticate the message, preventing tampering.
# 5. Replay attacks:  A nonce (random value) is included in the message and verified on the receiving end to prevent replay attacks.  The receiver *must* implement a mechanism to track previously used nonces to effectively prevent replay attacks. A timestamp could be added as well, but requires clock synchronization.
# 6., 7., 8., 9.  Key storage:  This code *does not* handle key storage.  The `secret_key` is passed as an argument.  In a real application, the `secret_key` should be loaded from a secure location.  Storing keys in plain text files, environment variables, or hardcoding them in the code is *highly discouraged*. Consider using Hardware Security Modules (HSMs), Key Management Systems (KMS), encrypted configuration files (encrypted with a separate key), or operating system keychains.
# 10. Multi-connection authentication:  This function should be called for each message sent over each connection to ensure authentication.
# 11. Key Rotation: In a long-lived system, it's good practice to rotate keys periodically to limit the impact of a potential key compromise. Strategies for implementing it include using a key version number in the message format. The receiver should maintain a mapping of key version numbers to the corresponding keys and support both the old and new keys for a certain period to allow for a smooth transition.
# 12. Side-Channel Attacks: While `hmac.compare_digest` mitigates timing attacks on HMAC comparison, other side-channel attacks (e.g., on AES encryption/decryption) are possible and may require further mitigation depending on the threat model. Consider using cryptographic libraries that provide constant-time implementations of AES and other algorithms.
# 13. PBKDF2 Iterations: The number of iterations for PBKDF2 should be chosen based on the available computing power and the desired security level. The iteration count should be increased over time as computing power increases.
# 14. CBC Mode and IV: It's crucial to use a *unique* IV for each encryption when using CBC mode. Reusing the same IV with the same key can compromise the security of CBC mode. This code generates a new IV for each message.

def generate_key(password, salt, iterations=100000):
    """Generates a secure key from a password and salt using PBKDF2."""
    kdf = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt,
        iterations  # Adjust the number of iterations as needed
    )
    return kdf

def send_encrypted(secret_key, channel, message, key_version=1):
    """
    Encrypts the message using AES, authenticates it with HMAC,
    and sends it over the channel.  Includes a nonce to prevent replay attacks.
    """

    # Generate a random nonce (number used once)
    nonce = get_random_bytes(16)  # 16 bytes for AES-CBC

    # Create an AES cipher object
    cipher = AES.new(secret_key, AES.MODE_CBC)  # Use CBC mode

    # Pad the message to be a multiple of the block size
    padded_message = pad(message.encode('utf-8'), AES.block_size)

    # Encrypt the message
    ciphertext = cipher.encrypt(padded_message)

    # Calculate HMAC for authentication
    hmac_obj = hmac.new(secret_key, digestmod=hashlib.sha256)
    hmac_obj.update(bytes([key_version])) # Include key version in HMAC
    hmac_obj.update(nonce)
    hmac_obj.update(cipher.iv)  # Include IV in HMAC calculation
    hmac_obj.update(ciphertext)
    hmac_value = hmac_obj.digest()

    # Construct the message to send: key_version + nonce + IV + ciphertext + HMAC
    message_to_send = bytes([key_version]) + nonce + cipher.iv + ciphertext + hmac_value

    # Send the message over the channel
    channel.send(message_to_send)


def receive_encrypted(secret_key, channel, seen_nonces):
    """
    Receives an encrypted message, verifies the HMAC, decrypts it,
    and returns the original message.  Raises an exception if verification fails.
    """
    received_message = channel.receive()

    if len(received_message) < 1 + 16 + AES.block_size + 32:  # key_version + nonce + IV + min ciphertext + HMAC
        raise ValueError("Invalid message length")

    key_version = received_message[0]
    received_message = received_message[1:]

    nonce = received_message[:16]
    iv = received_message[16:16 + AES.block_size]
    ciphertext = received_message[16 + AES.block_size:-32]
    received_hmac = received_message[-32:]

    # Nonce tracking (CRITICAL - MUST BE IMPLEMENTED)
    # Replace with a persistent storage mechanism (e.g., database, bloom filter)
    if nonce in seen_nonces:
        raise ValueError("Replay attack detected - nonce already used!")
    seen_nonces.add(nonce)
    # Consider implementing a strategy for managing the size of seen_nonces (e.g., time-based expiration).

    # Calculate HMAC to verify message integrity
    hmac_obj = hmac.new(secret_key, digestmod=hashlib.sha256)
    hmac_obj.update(bytes([key_version])) # Include key version in HMAC
    hmac_obj.update(nonce)
    hmac_obj.update(iv)
    hmac_obj.update(ciphertext)
    expected_hmac = hmac_obj.digest()

    # Verify HMAC
    if not hmac.compare_digest(received_hmac, expected_hmac):
        raise ValueError("HMAC verification failed - message tampered with!")

    # Create AES cipher object for decryption
    cipher = AES.new(secret_key, AES.MODE_CBC, iv=iv)

    # Decrypt the message
    padded_message = cipher.decrypt(ciphertext)

    # Unpad the message
    try:
        message = unpad(padded_message, AES.block_size).decode('utf-8')
    except ValueError:
        # Log the specific error on the server-side for debugging
        # logging.exception("Decryption failed due to invalid padding") # Requires import logging
        raise ValueError("Decryption failed") # Changed error message to be generic

    return message


class Channel:  # Dummy channel for demonstration
    def __init__(self):
        self.message = None

    def send(self, message):
        self.message = message

    def receive(self):
        return self.message


if __name__ == '__main__':
    # --- Example Usage ---
    # In a real application, the secret key should be securely generated and stored.
    # NEVER hardcode keys in your code!

    # --- Secure Key Generation and Storage Examples ---

    # 1. Using a password and salt to derive a key (for authentication, NOT long-term encryption):
    password = "my_secret_password"
    salt = os.urandom(16)  # Generate a random salt
    secret_key = generate_key(password, salt)
    # The salt *must* be stored along with the derived key (or a hash of the key) so that it can be used to re-derive the key during authentication.

    # 2. Generating a truly random key (for encryption):
    # Use os.urandom or secrets.token_bytes for cryptographically secure random key generation.
    # secret_key = os.urandom(32)  # 32 bytes for AES-256
    secret_key = secrets.token_bytes(32) # More modern and recommended

    # --- Key Storage ---
    # The secret_key should be stored securely using one of the following methods:
    #   - Hardware Security Modules (HSMs)
    #   - Key Management Systems (KMS)
    #   - Encrypted Configuration Files (encrypted with a separate key)
    #   - Operating System Keychains

    message = "This is a secret message!"

    # Create a dummy channel
    channel = Channel()

    # Initialize nonce tracking
    seen_nonces = set()

    # Send the encrypted message
    send_encrypted(secret_key, channel, message)

    # Receive and decrypt the message
    try:
        received_message = receive_encrypted(secret_key, channel, seen_nonces)
        print("Received message:", received_message)
    except ValueError as e:
        print("Error:", e)

    # Example of sending with a key version
    send_encrypted(secret_key, channel, "Another secret message", key_version=2)

    # To receive with key versioning, you'd need a key management system
    # and modify receive_encrypted to retrieve the correct key based on the key_version.

