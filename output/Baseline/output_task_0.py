import hashlib
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import base64

def generate_salt():
    """Generates a random salt for key derivation."""
    return os.urandom(16)

def derive_key(password, salt):
    """Derives a secure key from a password and salt using PBKDF2HMAC."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # Key length
        salt=salt,
        iterations=100000,  # High iteration count for security
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_data(data, key):
    """Encrypts data using Fernet symmetric encryption."""
    f = Fernet(key)
    return f.encrypt(data.encode())

def decrypt_data(data, key):
    """Decrypts data using Fernet symmetric encryption."""
    f = Fernet(key)
    return f.decrypt(data).decode()

def store_encrypted_data(data, filename, password):
    """Encrypts and stores data securely using key derivation and symmetric encryption."""
    salt = generate_salt()
    key = derive_key(password, salt)
    encrypted_data = encrypt_data(data, key)

    with open(filename, 'wb') as f:
        # Store salt, then encrypted data
        f.write(salt)
        f.write(encrypted_data)

def retrieve_and_decrypt_data(filename, password):
    """Retrieves and decrypts data securely."""
    try:
        with open(filename, 'rb') as f:
            salt = f.read(16)
            encrypted_data = f.read()  # Read the rest of the file
    except FileNotFoundError:
        return None # Handle the case where the file doesn't exist.

    key = derive_key(password, salt)
    try:
      decrypted_data = decrypt_data(encrypted_data, key)
      return decrypted_data
    except:
      return None # Or raise an exception to signal the authentication failed

def hash_data(data):
  """Hashes the data using SHA-256."""
  hasher = hashlib.sha256()
  hasher.update(data.encode('utf-8'))
  return hasher.hexdigest()

if __name__ == '__main__':
    # Example usage:
    device_id = "your_device_id_12345"
    filename = "hardware_id.dat"
    password = "secure_password" # This should be obtained securely (e.g., user input)
    
    # Store the device ID securely:
    store_encrypted_data(device_id, filename, password)

    # Retrieve and decrypt the device ID:
    retrieved_id = retrieve_and_decrypt_data(filename, password)

    if retrieved_id:
        print("Retrieved Device ID:", retrieved_id)
        # Verify with the original value if needed.
        if retrieved_id == device_id:
            print("Verification successful!")
        else:
            print("Verification failed!")
    else:
        print("Failed to retrieve or decrypt data.")

    #Example of hashing:
    hashed_id = hash_data(device_id)
    print("Hashed Device ID:", hashed_id)