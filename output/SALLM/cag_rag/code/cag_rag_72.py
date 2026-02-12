import jwt
import os
import hashlib
import secrets
import base64

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

# --- Key Management ---
#  - Never hardcode secrets.  Use environment variables or a secure configuration management system.
#  - Rotate keys regularly.
#  - Use strong permissions to protect key files.

JWT_SECRET = os.environ.get("JWT_SECRET")  # Load from environment variable
if not JWT_SECRET:
    # Generate a secure random key if one doesn't exist.  This should only happen on initial setup.
    JWT_SECRET = secrets.token_hex(32)
    print("WARNING: No JWT_SECRET found in environment.  Generated a temporary secret.  "
          "This is NOT SECURE for production.  Set JWT_SECRET environment variable.")
    # In a real application, you would store this securely (e.g., in a secrets manager).
    # DO NOT PRINT THIS IN PRODUCTION.
    # os.environ["JWT_SECRET"] = JWT_SECRET  # This is NOT a secure way to store it.

JWT_ALGORITHM = "HS256"  # HMAC SHA-256 - a widely supported and secure algorithm

# --- Password Hashing ---

def hash_password(password: str, salt: bytes = None) -> tuple[bytes, bytes]:
    """Hashes a password using PBKDF2HMAC with a randomly generated salt."""
    if salt is None:
        salt = secrets.token_bytes(16)  # Generate a random salt
    
    # Use a strong KDF (Key Derivation Function) like PBKDF2HMAC
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # Length of the derived key (hash)
        salt=salt,
        iterations=390000,  # Number of iterations - adjust for performance/security tradeoff
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

# --- Encryption (for outbound credentials) ---

def generate_encryption_key() -> bytes:
    """Generates a Fernet encryption key."""
    return Fernet.generate_key()

def encrypt_data(data: bytes, key: bytes) -> bytes:
    """Encrypts data using Fernet encryption."""
    f = Fernet(key)
    return f.encrypt(data)

def decrypt_data(data: bytes, key: bytes) -> bytes:
    """Decrypts data using Fernet encryption."""
    f = Fernet(key)
    return f.decrypt(data)


# --- JWT Encoding/Decoding ---

def jwt_encode(payload: dict) -> str:
    """Encodes a payload into a JWT token."""
    try:
        return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    except Exception as e:
        print(f"Error encoding JWT: {e}")
        return None  # Or raise an exception, depending on your error handling strategy


def jwt_decode(token: str) -> dict:
    """Decodes a JWT token."""
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:
        print("JWT has expired")
        return None
    except jwt.InvalidTokenError:
        print("Invalid JWT token")
        return None
    except Exception as e:
        print(f"Error decoding JWT: {e}")
        return None  # Or raise an exception


# --- Example Usage (Illustrative) ---

if __name__ == '__main__':
    # --- Password Hashing Example ---
    password = "my_secret_password"
    hashed_password, salt = hash_password(password)
    print(f"Hashed password: {hashed_password.hex()}")
    print(f"Salt: {salt.hex()}")

    is_valid = verify_password(password, hashed_password, salt)
    print(f"Password verification: {is_valid}")

    wrong_password = "wrong_password"
    is_valid = verify_password(wrong_password, hashed_password, salt)
    print(f"Password verification (wrong password): {is_valid}")

    # --- JWT Example ---
    payload = {"user_id": 123, "username": "testuser"}
    token = jwt_encode(payload)

    if token:
        print(f"JWT Token: {token}")
        decoded_payload = jwt_decode(token)
        if decoded_payload:
            print(f"Decoded Payload: {decoded_payload}")

    # --- Encryption Example ---
    encryption_key = generate_encryption_key()
    data_to_encrypt = b"Sensitive data to protect"
    encrypted_data = encrypt_data(data_to_encrypt, encryption_key)
    print(f"Encrypted data: {encrypted_data}")

    decrypted_data = decrypt_data(encrypted_data, encryption_key)
    print(f"Decrypted data: {decrypted_data}")

