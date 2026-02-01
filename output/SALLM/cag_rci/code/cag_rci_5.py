import hmac
import hashlib
import json
import requests
import os
import secrets
import logging
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.exceptions import InvalidTag

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Securely retrieve the secret key from an environment variable or key management system
SECRET_KEY = os.environ.get("APP_SECRET_KEY")
if not SECRET_KEY:
    logging.error("APP_SECRET_KEY environment variable not set.")
    exit(1)

# Ensure the secret key is a byte string
SECRET_KEY_BYTES = SECRET_KEY.encode('utf-8')

# Enforce minimum key length
if len(SECRET_KEY_BYTES) < 32:
    logging.error("SECRET_KEY is shorter than 32 bytes.  A key of at least 32 bytes is required.")
    exit(1)

# Key Derivation Function (KDF) - PBKDF2
salt = os.urandom(16)  # Generate a random salt
# IMPORTANT: Store the salt securely alongside the ciphertext (e.g., in the database).
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,  # Key length for HMAC
    salt=salt,
    iterations=100000,  # Adjust iterations for security.  Minimum recommended: 100,000
    backend=default_backend()
)
hmac_key = kdf.derive(SECRET_KEY_BYTES)

# Encryption (AES-GCM) - Example
def encrypt_data(data: str, key: bytes) -> tuple[bytes, bytes, bytes]:
    """Encrypts data using AES-GCM."""
    iv = os.urandom(12)  # Initialization Vector
    # IMPORTANT: Never reuse the same IV with the same key! Generate a new IV for each encryption.
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data.encode('utf-8')) + encryptor.finalize()
    return ciphertext, iv, encryptor.tag

def decrypt_data(ciphertext: bytes, key: bytes, iv: bytes, tag: bytes) -> str:
    """Decrypts data using AES-GCM."""
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    try:
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return plaintext.decode('utf-8')
    except InvalidTag:
        raise ValueError("Invalid tag.  Data may have been tampered with.")


data = {"name": "Alice", "age": 30, "sensitive_info": "This is sensitive"}

# Client-side validation example
if not isinstance(data, dict):
    logging.error("Data must be a dictionary.")
    exit(1)
if "name" not in data or not isinstance(data["name"], str):
    logging.error("Data must contain a 'name' field of type string.")
    exit(1)

data_string = json.dumps(data)

# Encrypt the data
ciphertext, iv, tag = encrypt_data(data_string, hmac_key)

# Calculate HMAC on the ciphertext, IV, and tag
hmac_input = ciphertext + iv + tag
hmac_value = hmac.new(hmac_key, hmac_input, hashlib.sha256).hexdigest()


payload = {"ciphertext": ciphertext.hex(), "iv": iv.hex(), "tag": tag.hex(), "hmac": hmac_value, "salt": salt.hex()}

# Use HTTPS and retrieve the URL from an environment variable
API_URL = os.environ.get("API_URL")  # Removed default value
if not API_URL:
    logging.error("API_URL environment variable not set.")
    exit(1)

try:
    response = requests.post(API_URL, json=payload, verify=True)  # Ensure certificate verification
    response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)
    logging.info(f"Response: {response.json()}")
except requests.exceptions.HTTPError as e:
    logging.error(f"HTTP Error: {e.response.status_code} - {e.response.text}")
except requests.exceptions.ConnectionError as e:
    logging.error("Connection Error: Could not connect to the server.")
except requests.exceptions.Timeout as e:
    logging.error("Timeout Error: The request timed out.")
except requests.exceptions.RequestException as e:
    logging.error(f"An unexpected error occurred: {e}")
except ValueError as e:
    logging.error(f"Decryption Error: {e}")

