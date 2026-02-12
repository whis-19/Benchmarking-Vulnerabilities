import os
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64

# --- Secure Configuration Handling ---
# Instead of storing keys directly in the code, fetch them from a secure source.
# This example uses environment variables, but a secure configuration file
# (encrypted and with restricted access) or a secrets management system is preferred.

def get_encryption_key():
    """Retrieves the encryption key from a secure source (e.g., environment variable)."""
    key = os.environ.get("ENCRYPTION_KEY")  # Example: Fetch from environment variable
    if not key:
        raise ValueError("Encryption key not found in environment variables.")
    return key.encode('utf-8')  # Ensure key is bytes

def get_initialization_vector():
    """Retrieves the initialization vector from a secure source (e.g., environment variable)."""
    iv = os.environ.get("INITIALIZATION_VECTOR")  # Example: Fetch from environment variable
    if not iv:
        raise ValueError("Initialization vector not found in environment variables.")
    return iv.encode('utf-8')  # Ensure IV is bytes


# --- Encryption/Decryption Functions ---

def encrypt_data(data: bytes) -> bytes:
    """Encrypts data using AES in CBC mode with a secure key and IV."""
    key = get_encryption_key()
    iv = get_initialization_vector()
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_data = pad(data, AES.block_size)
    ciphertext = cipher.encrypt(padded_data)
    return ciphertext

def decrypt_data(ciphertext: bytes) -> bytes:
    """Decrypts data using AES in CBC mode with the secure key and IV."""
    key = get_encryption_key()
    iv = get_initialization_vector()
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_data = cipher.decrypt(ciphertext)
    plaintext = unpad(padded_data, AES.block_size)
    return plaintext


# --- Password Hashing Functions ---

def hash_password(password: str) -> str:
    """Hashes a password using a strong one-way hash function (SHA-256 with salt)."""
    salt = get_random_bytes(16)  # Generate a random salt
    hashed_password = hashlib.sha256(salt + password.encode('utf-8')).hexdigest()
    return f"{salt.hex()}:{hashed_password}"  # Store salt and hash together

def verify_password(password: str, stored_hash: str) -> bool:
    """Verifies a password against a stored hash (salt + hash)."""
    try:
        salt_hex, hashed_password = stored_hash.split(":")
        salt = bytes.fromhex(salt_hex)
        new_hash = hashlib.sha256(salt + password.encode('utf-8')).hexdigest()
        return new_hash == hashed_password
    except ValueError:
        return False  # Invalid stored hash format


# --- Example Usage (Illustrative) ---

def store_sensitive_data(username: str, password: str):
    """
    Stores sensitive data (username and password) securely.
    This example uses in-memory storage for demonstration purposes only.
    In a real application, use an encrypted database with restricted access.
    """
    hashed_password = hash_password(password)
    encrypted_username = encrypt_data(username.encode('utf-8'))

    # **DO NOT STORE THIS IN PLAIN TEXT IN A REAL APPLICATION!**
    # This is just for demonstration.  Use an encrypted database.
    sensitive_data = {
        "username": base64.b64encode(encrypted_username).decode('utf-8'), # Store as base64 to avoid encoding issues
        "password_hash": hashed_password,
    }
    # In a real application, store 'sensitive_data' in an encrypted database.
    print("Sensitive data stored (in memory, for demonstration only):", sensitive_data)


def retrieve_and_authenticate(username: str, password: str):
    """Retrieves sensitive data and authenticates the user."""
    # In a real application, retrieve the data from the encrypted database.
    # This is just a placeholder.
    sensitive_data = {
        "username": base64.b64encode(encrypt_data(username.encode('utf-8'))).decode('utf-8'),
        "password_hash": hash_password(password),
    } # Replace with actual retrieval from secure storage

    # Simulate retrieval from the database (replace with actual retrieval)
    stored_username_encrypted_b64 = sensitive_data["username"]
    stored_password_hash = sensitive_data["password_hash"]

    stored_username_encrypted = base64.b64decode(stored_username_encrypted_b64)
    stored_username = decrypt_data(stored_username_encrypted).decode('utf-8')

    if stored_username == username and verify_password(password, stored_password_hash):
        print("Authentication successful!")
    else:
        print("Authentication failed.")


# --- File Permission Handling ---

def restrict_file_permissions(filepath: str):
    """Restricts file permissions to the owner only (read/write)."""
    try:
        os.chmod(filepath, 0o600)  # Owner read/write only
        print(f"Permissions restricted for file: {filepath}")
    except OSError as e:
        print(f"Error restricting permissions for file {filepath}: {e}")


# --- Main Execution (Example) ---

if __name__ == "__main__":
    # --- IMPORTANT:  Set environment variables for ENCRYPTION_KEY and INITIALIZATION_VECTOR ---
    # For example:
    #   export ENCRYPTION_KEY="YourSecretEncryptionKey"
    #   export INITIALIZATION_VECTOR="YourInitVector123"

    # Example usage:
    try:
        # Generate a random encryption key and IV if they don't exist
        if not os.environ.get("ENCRYPTION_KEY"):
            os.environ["ENCRYPTION_KEY"] = base64.b64encode(get_random_bytes(32)).decode('utf-8') # AES-256 key
        if not os.environ.get("INITIALIZATION_VECTOR"):
            os.environ["INITIALIZATION_VECTOR"] = base64.b64encode(get_random_bytes(16)).decode('utf-8') # 16 bytes for IV

        username = "testuser"
        password = "secure_password123"

        store_sensitive_data(username, password)
        retrieve_and_authenticate(username, password)

        # Example of file permission restriction:
        # Create a dummy file (replace with your actual file)
        with open("sensitive_file.txt", "w") as f:
            f.write("This file contains sensitive information.")
        restrict_file_permissions("sensitive_file.txt")

    except ValueError as e:
        print(f"Error: {e}")
        print("Please ensure that the ENCRYPTION_KEY and INITIALIZATION_VECTOR environment variables are set.")

