from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
import hashlib
import os
import base64

# --- Secure Configuration Management ---
# Instead of storing keys directly in the code, we'll use a key derivation function (KDF)
# to generate an encryption key from a master password.  The master password itself
# should be stored securely (e.g., using a hardware security module, or a password manager).
# This example uses a hardcoded master password for demonstration purposes only.
# In a real application, NEVER hardcode the master password.

MASTER_PASSWORD = "ThisIsAVeryStrongMasterPasswordChangeMe!"  # NEVER HARDCODE IN REALITY
SALT_LENGTH = 16
ITERATIONS = 100000  # Adjust for performance vs. security
KEY_LENGTH = 32  # AES-256 key length
IV_LENGTH = 16  # AES Initialization Vector length

def derive_key(password, salt, iterations=ITERATIONS, key_length=KEY_LENGTH):
    """Derives a key from a password using PBKDF2."""
    password = password.encode('utf-8')
    salt = salt.encode('utf-8')
    return hashlib.pbkdf2_hmac('sha256', password, salt, iterations, dklen=key_length)

def generate_salt(length=SALT_LENGTH):
    """Generates a random salt."""
    return base64.b64encode(get_random_bytes(length)).decode('utf-8')

def encrypt_data(data, master_password=MASTER_PASSWORD):
    """Encrypts data using AES-256 with a derived key and a random IV."""
    salt = generate_salt()
    key = derive_key(master_password, salt)
    iv = get_random_bytes(IV_LENGTH)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_data = pad(data.encode('utf-8'), AES.block_size)
    ciphertext = cipher.encrypt(padded_data)
    # Store salt and IV along with the ciphertext for decryption
    return base64.b64encode(salt.encode('utf-8') + iv + ciphertext).decode('utf-8')

def decrypt_data(encrypted_data, master_password=MASTER_PASSWORD):
    """Decrypts data encrypted with encrypt_data."""
    try:
        encrypted_data = base64.b64decode(encrypted_data.encode('utf-8'))
        salt = encrypted_data[:SALT_LENGTH].decode('utf-8')
        iv = encrypted_data[SALT_LENGTH:SALT_LENGTH + IV_LENGTH]
        ciphertext = encrypted_data[SALT_LENGTH + IV_LENGTH:]

        key = derive_key(master_password, salt)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded_data = cipher.decrypt(ciphertext)
        unpadded_data = pad(padded_data, AES.block_size)
        return unpadded_data.decode('utf-8')
    except Exception as e:
        print(f"Decryption error: {e}")
        return None  # Or raise an exception, depending on the use case

# --- Password Hashing ---

def hash_password(password):
    """Hashes a password using a strong one-way hash (bcrypt)."""
    salt = generate_salt()
    password = password.encode('utf-8')
    salt = salt.encode('utf-8')
    hashed_password = hashlib.pbkdf2_hmac('sha256', password, salt, ITERATIONS)
    return base64.b64encode(salt.encode('utf-8') + hashed_password).decode('utf-8')

def verify_password(password, stored_hash):
    """Verifies a password against a stored hash."""
    try:
        stored_hash = base64.b64decode(stored_hash.encode('utf-8'))
        salt = stored_hash[:SALT_LENGTH].decode('utf-8')
        hashed_password = stored_hash[SALT_LENGTH:]
        password = password.encode('utf-8')
        salt = salt.encode('utf-8')
        new_hash = hashlib.pbkdf2_hmac('sha256', password, salt, ITERATIONS)
        return new_hash == hashed_password
    except Exception as e:
        print(f"Password verification error: {e}")
        return False

# --- Example Usage (Illustrative) ---

if __name__ == '__main__':
    # --- Data Encryption Example ---
    sensitive_data = "My Secret Data"
    encrypted_data = encrypt_data(sensitive_data)
    print(f"Encrypted data: {encrypted_data}")

    decrypted_data = decrypt_data(encrypted_data)
    print(f"Decrypted data: {decrypted_data}")

    # --- Password Hashing Example ---
    password = "MySecurePassword123"
    hashed_password = hash_password(password)
    print(f"Hashed password: {hashed_password}")

    is_valid = verify_password(password, hashed_password)
    print(f"Password is valid: {is_valid}")

    wrong_password = "WrongPassword"
    is_valid = verify_password(wrong_password, hashed_password)
    print(f"Wrong password is valid: {is_valid}")

