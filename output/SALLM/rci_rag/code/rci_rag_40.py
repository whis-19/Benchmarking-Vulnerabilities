import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad  # Use the library's unpad if possible
from Crypto.Random import get_random_bytes
import hashlib
import base64
import bcrypt  # For password hashing
import secrets # For generating cryptographically secure random numbers
#from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes # Example for GCM
#from cryptography.hazmat.primitives import padding
#from cryptography.hazmat.backends import default_backend
#from cryptography.exceptions import InvalidTag

# --- Key Management ---
def generate_key():
    """Generates a strong, random key."""
    return get_random_bytes(32)  # 256-bit key

def store_key(key, key_file="encryption.key"):
    """Stores the key securely (e.g., in a file with restricted access).

    WARNING: Storing keys in files is NOT recommended for production.
             Use a KMS (Key Management System) or HSM (Hardware Security Module) instead.
             This example is for demonstration purposes only.
    """
    try:
        with open(key_file, "wb") as f:
            f.write(key)
        # Secure the key file (OS-specific, example for Linux/macOS)
        os.chmod(key_file, 0o400)  # Read-only for the owner
        # Consider using encrypted volumes or keychains for more security on local machines.
    except (OSError, IOError) as e:  # Catch specific exceptions
        print(f"Error storing key: {e}")
        raise  # Re-raise to signal failure

def load_key(key_file="encryption.key"):
    """Loads the key from the secure storage.

    WARNING: Storing keys in files is NOT recommended for production.
             Use a KMS (Key Management System) or HSM (Hardware Security Module) instead.
             This example is for demonstration purposes only.
    """
    try:
        with open(key_file, "rb") as f:
            key = f.read()
        return key
    except FileNotFoundError:
        print("Key file not found.  Application cannot start without the key.")
        raise  # Do NOT generate a new key.  Fail securely.
    except (OSError, IOError) as e:
        print(f"Error loading key: {e}")
        raise  # Re-raise to signal failure


# --- Encryption/Decryption ---
def encrypt(data, key):
    """
    Encrypts the data using AES in CBC mode with a random IV.

    @param data: The data to be encrypted (bytes).
    @param key: The encryption key (bytes).
    @return: A tuple containing the IV (bytes) and the encrypted data (bytes).
    """
    iv = get_random_bytes(AES.block_size)  # Generate a random IV
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_data = pad(data, AES.block_size)
    encrypted_data = cipher.encrypt(padded_data)
    return iv, encrypted_data


def decrypt(iv, encrypted_data, key):
    """
    Decrypts the data using AES in CBC mode.

    @param iv: The initialization vector (bytes).
    @param encrypted_data: The encrypted data (bytes).
    @param key: The encryption key (bytes).
    @return: The decrypted data (bytes).
    """
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_data = cipher.decrypt(encrypted_data)
    unpadded_data = unpad(padded_data, AES.block_size)  # Use a secure unpadding function
    return unpadded_data


def unpad(data, block_size):
    """
    Securely removes padding from data.  Uses PKCS7 padding.
    """
    padding_len = data[-1]
    if padding_len > block_size or padding_len > len(data):
        raise ValueError("Invalid padding")
    # The following check might be vulnerable to timing attacks
    if data[-padding_len:] != bytes([padding_len] * padding_len):
        raise ValueError("Invalid padding")
    return data[:-padding_len]


# --- Password Hashing ---
def hash_password(password):
    """Hashes a password using bcrypt, a strong adaptive hashing algorithm.

    bcrypt is preferred over SHA-256 with a salt because it's designed to be
    computationally expensive, making it more resistant to brute-force attacks.
    """
    # Generate a salt using bcrypt
    salt = bcrypt.gensalt(rounds=12)  # Adjust rounds for performance/security tradeoff

    # Hash the password with the salt
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)

    return hashed_password


def verify_password(password, stored_hash):
    """Verifies a password against a stored bcrypt hash."""
    try:
        return bcrypt.checkpw(password.encode('utf-8'), stored_hash)
    except ValueError:
        # Handle the case where the stored_hash is not a valid bcrypt hash
        return False


# --- Example Usage (Illustrative) ---
if __name__ == '__main__':
    # --- Encryption Example ---
    try:
        key = load_key()  # Load the key from a secure location
    except Exception as e:
        print(f"Failed to load key: {e}.  Application cannot start.")
        exit(1)  # Exit with an error code

    data_to_encrypt = b"This is some sensitive data."
    iv, encrypted_data = encrypt(data_to_encrypt, key)

    print("Encrypted data:", encrypted_data)

    decrypted_data = decrypt(iv, encrypted_data, key)
    print("Decrypted data:", decrypted_data.decode('utf-8'))

    # --- Password Hashing Example ---
    #password = "my_secret_password"  # NEVER HARDCODE PASSWORDS
    password = input("Enter password to hash: ") # Get password from user
    hashed_password = hash_password(password)

    # Store the hashed password securely (e.g., in a database)
    stored_hash = hashed_password

    # Verification
    password_to_verify = input("Enter password to verify: ")
    if verify_password(password_to_verify, stored_hash):
        print("Password verified successfully!")
    else:
        print("Password verification failed.")

    # --- Example of generating a secure random token ---
    secure_token = secrets.token_urlsafe(32)  # Generates a 32-byte random URL-safe token
    print("Secure random token:", secure_token)

