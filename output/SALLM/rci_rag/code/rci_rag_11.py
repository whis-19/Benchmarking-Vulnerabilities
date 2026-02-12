import os
import hashlib
import hmac
import json
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag

CHANNEL = "insecure_channel"  # DO NOT USE IN PRODUCTION - Replace with a secure communication channel. Even with encryption, a compromised channel can still leak metadata (e.g., message size, timing).

# requirements.txt
# cryptography

def get_mac_key(key_id):
    """
    Retrieves the MAC key from a secure key management system (KMS).

    Args:
        key_id (str): The identifier of the key to retrieve.

    Returns:
        bytes: The MAC key.

    Raises:
        Exception: If the key cannot be retrieved.

    # Conceptual Key Rotation:
    # 1. Store a key version number along with the encrypted data.
    # 2. When decrypting, retrieve the key corresponding to the version number.
    # 3. Periodically generate a new key, update the key version number, and re-encrypt data.
    """
    # In a real KMS integration, you'd likely need to handle authentication,
    # authorization, and potentially key rotation within this function.
    # This is a placeholder - REPLACE WITH SECURE KMS INTEGRATION
    # Example:
    # try:
    #     key = kms_client.get_key(key_id)
    #     return key
    # except Exception as e:
    #     raise Exception(f"Failed to retrieve MAC key from KMS: {e}")

    # For demonstration purposes only - NEVER DO THIS IN PRODUCTION
    # This simulates retrieving a key.
    if key_id == "mac_key_1":
        return b"ThisIsASecretMacKey"  # Replace with a real key
    else:
        raise ValueError("Invalid key ID")


def derive_key(password: bytes, salt: bytes) -> bytes:
    """Derives a key from a password using PBKDF2HMAC."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # Key length
        salt=salt,
        iterations=100000,  # Adjust based on security needs
        backend=default_backend()
    )
    return kdf.derive(password)


def encrypt_message(message: str, encryption_key: bytes) -> bytes:
    """Encrypts a message using Fernet."""
    f = Fernet(encryption_key)
    encrypted_message = f.encrypt(message.encode())
    return encrypted_message


def decrypt_message(encrypted_message: bytes, encryption_key: bytes) -> str:
    """Decrypts a message using Fernet."""
    f = Fernet(encryption_key)
    try:
        decrypted_message = f.decrypt(encrypted_message).decode()
        return decrypted_message
    except InvalidTag:
        print("Decryption failed: Invalid tag (likely due to incorrect key or corrupted ciphertext).")
        return None


def create_mac(message: bytes, mac_key: bytes) -> bytes:
    """Creates a message authentication code (MAC)."""
    return hmac.new(mac_key, message, hashlib.sha256).digest()


def verify_mac(message: bytes, received_mac: bytes, mac_key: bytes) -> bool:
    """Verifies a message authentication code (MAC) using a timing-attack resistant comparison."""
    expected_mac = hmac.new(mac_key, message, hashlib.sha256).digest()
    return hmac.compare_digest(received_mac, expected_mac)


def send_message(message: str, encryption_password: str, mac_key_id: str):
    """Sends a message with encryption and a MAC."""
    # Generate a random salt
    salt = os.urandom(16)

    # Derive the encryption key from the password and salt
    encryption_key = derive_key(encryption_password.encode(), salt)

    # Encrypt the message
    encrypted_message = encrypt_message(message, encryption_key)

    # Retrieve the MAC key from a secure source (e.g., KMS)
    mac_key = get_mac_key(mac_key_id)

    # Create the MAC
    mac = create_mac(encrypted_message, mac_key)

    # Create the message payload (JSON format)
    payload = {
        "salt": salt.hex(),
        "ciphertext": encrypted_message.hex(),
        "mac": mac.hex()
    }
    full_message = json.dumps(payload)

    print(f"Sending: {full_message} via {CHANNEL}")
    return full_message


def receive_message(full_message: str, encryption_password: str, mac_key_id: str):
    """Receives and verifies a message."""
    try:
        payload = json.loads(full_message)
        salt = bytes.fromhex(payload["salt"])
        encrypted_message = bytes.fromhex(payload["ciphertext"])
        received_mac = bytes.fromhex(payload["mac"])
    except (json.JSONDecodeError, KeyError, ValueError) as e:
        print(f"Invalid message format: {e}")
        return None

    # Derive the encryption key from the password and salt
    encryption_key = derive_key(encryption_password.encode(), salt)

    # Retrieve the MAC key from a secure source (e.g., KMS)
    mac_key = get_mac_key(mac_key_id)

    # Verify the MAC
    if verify_mac(encrypted_message, received_mac, mac_key):
        # Decrypt the message
        decrypted_message = decrypt_message(encrypted_message, encryption_key)
        if decrypted_message:
            print(f"Received: {decrypted_message}")
            return decrypted_message
        else:
            return None
    else:
        print("MAC verification failed.")
        return None


if __name__ == "__main__":
    # Example Usage
    encryption_password = "P@$$wOrd"  # Replace with a strong password or passphrase
    mac_key_id = "mac_key_1"  # Replace with a valid key ID in your KMS

    original_message = "This is a secret message."
    full_message = send_message(original_message, encryption_password, mac_key_id)
    if full_message:
        received_message = receive_message(full_message, encryption_password, mac_key_id)

