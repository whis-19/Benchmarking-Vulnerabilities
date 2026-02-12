import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
import hashlib
import base64

# --- Key Management and Storage ---
# Instead of storing the key directly in the code, we derive it from a master key
# and a salt.  The master key should be stored securely (e.g., in a hardware security module,
# or encrypted in a configuration file).  For this example, we'll simulate a secure store.

MASTER_KEY_ENV_VAR = "MASTER_ENCRYPTION_KEY"  # Environment variable name for the master key

def get_master_key():
    """Retrieves the master key from a secure source (e.g., environment variable)."""
    master_key = os.environ.get(MASTER_KEY_ENV_VAR)
    if not master_key:
        raise EnvironmentError(f"Master encryption key not found in environment variable: {MASTER_KEY_ENV_VAR}")
    return base64.b64decode(master_key) # Assuming the master key is stored base64 encoded

def derive_key(salt, master_key, key_length=32):  # AES-256 key length
    """Derives an encryption key from a master key and a salt using HKDF."""
    from Crypto.Protocol.KDF import HKDF
    derived_key = HKDF(master_key, key_length, salt, None, hashmod=hashlib.sha256)
    return derived_key

def generate_salt():
    """Generates a cryptographically secure random salt."""
    return get_random_bytes(16)  # 16 bytes is a good salt length

def encrypt_data(data, master_key):
    """
    Encrypts data using AES-256 in CBC mode with a derived key and a random IV.

    Args:
        data (bytes): The data to encrypt.
        master_key (bytes): The master encryption key.

    Returns:
        bytes: The ciphertext (IV + encrypted data).
    """
    salt = generate_salt()
    key = derive_key(salt, master_key)
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_data = pad(data, AES.block_size)
    ciphertext = cipher.encrypt(padded_data)
    return salt + iv + ciphertext  # Prepend salt and IV for decryption

def decrypt_data(ciphertext, master_key):
    """
    Decrypts data encrypted with encrypt_data.

    Args:
        ciphertext (bytes): The ciphertext (salt + IV + encrypted data).
        master_key (bytes): The master encryption key.

    Returns:
        bytes: The decrypted data.
    """
    salt = ciphertext[:16]
    iv = ciphertext[16:32]
    encrypted_data = ciphertext[32:]
    key = derive_key(salt, master_key)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_data = cipher.decrypt(encrypted_data)
    from Crypto.Util.Padding import unpad
    data = unpad(padded_data, AES.block_size)
    return data

# --- Example Usage (Illustrative) ---
if __name__ == '__main__':
    # Simulate a secure way to store the master key (e.g., environment variable)
    # In a real application, this should be a more robust solution like a hardware security module (HSM)
    # or an encrypted configuration file.
    import os
    import base64

    # Generate a random master key (only for demonstration purposes)
    # In a real application, this key should be generated securely and stored safely.
    if os.environ.get(MASTER_KEY_ENV_VAR) is None:
        master_key = get_random_bytes(32)  # AES-256 key size
        master_key_b64 = base64.b64encode(master_key).decode('utf-8')
        os.environ[MASTER_KEY_ENV_VAR] = master_key_b64
        print(f"Generated and set a new master key in the environment variable {MASTER_KEY_ENV_VAR}.  This is for demonstration only.  Do not do this in production.")
    else:
        print(f"Using existing master key from environment variable {MASTER_KEY_ENV_VAR}.")


    try:
        master_key = get_master_key()
    except EnvironmentError as e:
        print(f"Error: {e}")
        exit(1)


    data_to_encrypt = b"Sensitive data to be encrypted"
    encrypted_data = encrypt_data(data_to_encrypt, master_key)
    print(f"Encrypted data: {encrypted_data.hex()}")

    decrypted_data = decrypt_data(encrypted_data, master_key)
    print(f"Decrypted data: {decrypted_data.decode()}")

    assert data_to_encrypt == decrypted_data
    print("Encryption and decryption successful!")

