import os
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidTag
import base64

# --- Key Management and Storage (Guidelines 3, 7, 9, 13) ---
#  Instead of directly storing the key in the code, we derive it from a master key
#  using a key derivation function (KDF) like HKDF or Argon2.  This example uses HKDF.
#  The master key should be stored securely (e.g., in a hardware security module,
#  encrypted configuration file, or retrieved from a secure key management system).
#  For demonstration purposes, we'll simulate a stored master key.  NEVER hardcode
#  a real master key in your code.

MASTER_KEY_LOCATION = "path/to/secure/master_key_storage"  # Replace with actual secure storage

def _load_master_key():
    """Loads the master key from secure storage.  Replace with your actual implementation."""
    # In a real application, this would load the key from a secure location.
    # For demonstration, we use a placeholder.
    # NEVER hardcode a real master key.
    # Example: Read from an encrypted file, retrieve from a KMS, etc.
    # return b"ThisIsAStrongMasterKeyThatShouldBeStoredSecurely"  # INSECURE!
    try:
        with open(MASTER_KEY_LOCATION, "rb") as f:
            return f.read()
    except FileNotFoundError:
        print(f"Master key file not found at {MASTER_KEY_LOCATION}.  Generating a new one (FOR DEMO ONLY).")
        master_key = os.urandom(32)  # Generate a random key
        with open(MASTER_KEY_LOCATION, "wb") as f:
            f.write(master_key)
        return master_key


def _derive_key(salt: bytes, info: bytes = b"encryption_key") -> bytes:
    """Derives an encryption key from the master key using HKDF."""
    master_key = _load_master_key()
    hkdf = hashes.HKDF(
        algorithm=hashes.SHA256(),
        length=32,  # AES-256 key size
        salt=salt,
        info=info,
        backend=default_backend()
    )
    return hkdf.derive(master_key)


def getEncryptionKey(data: bytes) -> bytes:
    """
    Encrypts the given data using AES-GCM.

    Args:
        data: The bytes to encrypt.

    Returns:
        A tuple containing:
            - The ciphertext (bytes).
            - The associated data (bytes).
            - The nonce (bytes).
    """
    # --- Cryptographically Secure Random Number Generation (Guideline 4) ---
    salt = os.urandom(16)  # Generate a random salt
    key = _derive_key(salt)
    nonce = os.urandom(16)  # Generate a random nonce

    # --- Use Strong, Modern Cryptographic Algorithms (Guideline 1) ---
    # AES-GCM is a modern, authenticated encryption mode.
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()

    # --- Authenticated Encryption ---
    # GCM provides authenticated encryption, ensuring both confidentiality and integrity.
    associated_data = b"authenticated but not encrypted payload"  # Optional associated data
    encryptor.authenticate_additional_data(associated_data)

    ciphertext = encryptor.update(data) + encryptor.finalize()

    # --- Proper Key Management (Guideline 3) ---
    # The key is derived, not stored directly.  The master key is assumed to be
    # stored securely.

    # --- Return all necessary components for decryption ---
    return base64.b64encode(salt), base64.b64encode(nonce), base64.b64encode(associated_data), base64.b64encode(ciphertext)


def decrypt_data(salt_b64: bytes, nonce_b64: bytes, associated_data_b64: bytes, ciphertext_b64: bytes) -> bytes:
    """
    Decrypts data encrypted with AES-GCM.

    Args:
        salt_b64: The base64 encoded salt used for key derivation.
        nonce_b64: The base64 encoded nonce used during encryption.
        associated_data_b64: The base64 encoded associated data.
        ciphertext_b64: The base64 encoded ciphertext.

    Returns:
        The decrypted data (bytes).

    Raises:
        InvalidTag: If the ciphertext has been tampered with.
    """
    salt = base64.b64decode(salt_b64)
    nonce = base64.b64decode(nonce_b64)
    associated_data = base64.b64decode(associated_data_b64)
    ciphertext = base64.b64decode(ciphertext_b64)

    key = _derive_key(salt)

    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
    decryptor = cipher.decryptor()
    decryptor.authenticate_additional_data(associated_data)

    try:
        return decryptor.update(ciphertext) + decryptor.finalize()
    except InvalidTag:
        raise  # Re-raise the exception to indicate tampering


# --- Example Usage ---
if __name__ == "__main__":
    # Example usage
    plaintext = b"Sensitive data to be encrypted"
    salt_b64, nonce_b64, associated_data_b64, ciphertext_b64 = getEncryptionKey(plaintext)

    print(f"Salt (Base64): {salt_b64.decode()}")
    print(f"Nonce (Base64): {nonce_b64.decode()}")
    print(f"Associated Data (Base64): {associated_data_b64.decode()}")
    print(f"Ciphertext (Base64): {ciphertext_b64.decode()}")

    try:
        decrypted_data = decrypt_data(salt_b64, nonce_b64, associated_data_b64, ciphertext_b64)
        print(f"Decrypted data: {decrypted_data.decode()}")
        assert decrypted_data == plaintext
    except InvalidTag:
        print("Decryption failed: Data has been tampered with!")

    # --- Password Hashing Example (Guidelines 6, 8, 9) ---
    # This is a separate example for password hashing.
    password = "my_secret_password".encode('utf-8')
    salt = os.urandom(16)  # Generate a random salt for each password
    hashed_password = hashlib.pbkdf2_hmac('sha256', password, salt, 100000)  # Use PBKDF2

    # Store the salt and hashed password securely (e.g., in a database).
    # Example:
    # stored_salt = base64.b64encode(salt).decode('utf-8')
    # stored_hashed_password = base64.b64encode(hashed_password).decode('utf-8')

    # --- Authentication Example (Guideline 6) ---
    # During authentication, retrieve the stored salt and hashed password.
    # Example:
    # retrieved_salt = base64.b64decode(stored_salt.encode('utf-8'))
    # retrieved_hashed_password = base64.b64decode(stored_hashed_password.encode('utf-8'))

    # Verify the password:
    # new_hashed_password = hashlib.pbkdf2_hmac('sha256', password, retrieved_salt, 100000)
    # if new_hashed_password == retrieved_hashed_password:
    #     print("Authentication successful!")
    # else:
    #     print("Authentication failed!")

