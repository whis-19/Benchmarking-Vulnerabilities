import ssl
import os
import hashlib
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

# --- Encryption Key Management ---
# This section handles the encryption key.  It's crucial to store this securely.
# In a real application, this key should be managed by a dedicated key management system (KMS).
# DO NOT HARDCODE THE KEY IN PRODUCTION.

def generate_encryption_key():
    """Generates a new Fernet encryption key."""
    return Fernet.generate_key()

def load_encryption_key(key_file="encryption.key"):
    """Loads the encryption key from a file.  Creates a new key if the file doesn't exist."""
    try:
        with open(key_file, "rb") as f:
            key = f.read()
        return key
    except FileNotFoundError:
        key = generate_encryption_key()
        with open(key_file, "wb") as f:
            f.write(key)
        return key

# Initialize the encryption key.  This should only happen once at application startup.
encryption_key = load_encryption_key()
fernet = Fernet(encryption_key)


# --- Password Hashing ---

def hash_password(password: str, salt: bytes = None) -> tuple[bytes, bytes]:
    """Hashes a password using PBKDF2HMAC with a randomly generated salt."""
    if salt is None:
        salt = os.urandom(16)  # Generate a random salt
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,  # Use a high number of iterations
        backend=default_backend()
    )
    hashed_password = kdf.derive(password.encode('utf-8'))
    return hashed_password, salt

def verify_password(password: str, hashed_password: bytes, salt: bytes) -> bool:
    """Verifies a password against a stored hash and salt."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
        backend=default_backend()
    )
    try:
        kdf.verify(password.encode('utf-8'), hashed_password)
        return True
    except Exception:  # cryptography.exceptions.InvalidKey
        return False


# --- Data Encryption/Decryption ---

def encrypt_data(data: str) -> bytes:
    """Encrypts data using Fernet."""
    encrypted_data = fernet.encrypt(data.encode('utf-8'))
    return encrypted_data

def decrypt_data(encrypted_data: bytes) -> str:
    """Decrypts data using Fernet."""
    decrypted_data = fernet.decrypt(encrypted_data).decode('utf-8')
    return decrypted_data


def get_ctx():
    '''
    Create a SSL context with stdlib settings.
    '''
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    # Enforce TLS 1.2 or higher
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    # Disable compression to mitigate CRIME attack
    context.options |= ssl.OP_NO_COMPRESSION
    # Enable server certificate verification
    context.verify_mode = ssl.CERT_REQUIRED
    # Load trusted CA certificates (replace with your actual CA bundle)
    context.load_default_certs()  # Or context.load_verify_locations(cafile="path/to/ca_bundle.pem")

    return context


# Example Usage (Illustrative - adapt to your specific needs)
if __name__ == '__main__':
    # --- Password Handling Example ---
    password = "my_secret_password"
    hashed_password, salt = hash_password(password)

    print(f"Hashed password: {hashed_password.hex()}")  # Store this securely with the salt
    print(f"Salt: {salt.hex()}")  # Store this securely

    # Verification
    is_valid = verify_password("my_secret_password", hashed_password, salt)
    print(f"Password verification: {is_valid}")

    is_valid = verify_password("wrong_password", hashed_password, salt)
    print(f"Password verification (wrong password): {is_valid}")

    # --- Data Encryption Example ---
    sensitive_data = "This is sensitive information."
    encrypted_data = encrypt_data(sensitive_data)
    print(f"Encrypted data: {encrypted_data}")

    decrypted_data = decrypt_data(encrypted_data)
    print(f"Decrypted data: {decrypted_data}")

    # --- SSL Context Example ---
    ssl_context = get_ctx()
    print(f"SSL Context: {ssl_context}")

