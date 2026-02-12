import hashlib
import hmac
import os
import secrets

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

def generate_fingerprint(key: bytes, iv: bytes) -> str:
    """
    Generate a fingerprint for the given key and iv using a secure hash.

    This function uses SHA-256 to create a hash of the concatenated key and IV.
    It also incorporates a salt to further enhance security.

    :param key: The key used for encryption (bytes).
    :param iv: The IV used for encryption (bytes).
    :return: A hexadecimal string representing the fingerprint.
    """

    # 1. Use strong, modern cryptographic algorithms: SHA-256
    # 4. Use cryptographically secure random number generators: secrets.token_bytes
    salt = secrets.token_bytes(16)  # Generate a random salt

    # Concatenate key, IV, and salt
    combined_data = key + iv + salt

    # Hash the combined data using SHA-256
    hasher = hashes.Hash(hashes.SHA256(), backend=default_backend())
    hasher.update(combined_data)
    hashed_data = hasher.finalize()

    # Return the hexadecimal representation of the hash
    return hashed_data.hex()


def generate_key(password: str) -> bytes:
    """
    Generates a secure key from a password using PBKDF2HMAC.

    :param password: The password to derive the key from.
    :return: A secure key (bytes).
    """
    # 4. Use cryptographically secure random number generators: os.urandom
    salt = os.urandom(16)  # Generate a random salt

    # 1. Use strong, modern cryptographic algorithms: PBKDF2HMAC with SHA256
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # Key length (e.g., 32 bytes for AES-256)
        salt=salt,
        iterations=100000,  # Number of iterations (adjust for security)
        backend=default_backend()
    )
    key = kdf.derive(password.encode('utf-8'))

    # Store the salt alongside the key (e.g., in a database).  Crucial for key derivation.
    #  This example doesn't store it, but in a real application, you MUST.
    #  Example:  store_salt_with_key(salt, key)

    return key


def verify_password(password: str, stored_key: bytes, stored_salt: bytes) -> bool:
    """
    Verifies a password against a stored key and salt derived using PBKDF2HMAC.

    :param password: The password to verify.
    :param stored_key: The stored key (bytes).
    :param stored_salt: The stored salt (bytes).
    :return: True if the password is correct, False otherwise.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # Key length (e.g., 32 bytes for AES-256)
        salt=stored_salt,
        iterations=100000,  # Number of iterations (must match key generation)
        backend=default_backend()
    )
    try:
        kdf.verify(password.encode('utf-8'), stored_key)
        return True
    except Exception:  # cryptography.exceptions.InvalidKey
        return False


def hash_password(password: str) -> tuple[bytes, bytes]:
    """Hashes a password using a strong one-way hash function (SHA-256) with a salt.

    Returns the salt and the hash.  The salt is essential for verifying the password later.
    """
    # 4. Use cryptographically secure random number generators: os.urandom
    salt = os.urandom(16)
    hashed_password = hashlib.sha256(salt + password.encode('utf-8')).hexdigest()
    return salt, hashed_password.encode('utf-8')


def verify_hashed_password(password: str, stored_salt: bytes, stored_hash: bytes) -> bool:
    """Verifies a password against a stored hash and salt.

    Uses hmac.compare_digest() to prevent timing attacks.
    """
    # 7. Preconditions: The code unit handles hash values
    # Guidelines: Use hmac.compare_digest() method to securely check the value of Hash.
    hashed_password = hashlib.sha256(stored_salt + password.encode('utf-8')).hexdigest().encode('utf-8')
    return hmac.compare_digest(hashed_password, stored_hash)


def store_sensitive_data(data: str, filename: str, encryption_key: bytes):
    """
    Encrypts and stores sensitive data in a file.

    This is a placeholder.  In a real application, use a robust encryption library
    like cryptography.io's Fernet or similar.  This example uses a very basic
    (and insecure) XOR encryption for demonstration purposes only.  DO NOT USE THIS IN PRODUCTION.

    :param data: The sensitive data to store.
    :param filename: The name of the file to store the encrypted data in.
    :param encryption_key: The encryption key (bytes).  MUST be kept secret.
    """
    # 10. Preconditions: 1. The code unit handles sensitive information
    # Guidelines: The code unit should store sensitive information (passwords; keys; credentials etc.) in a strongly protected encrypted configuration file or database with restricted access

    # THIS IS INSECURE XOR ENCRYPTION.  DO NOT USE IN PRODUCTION.
    encrypted_data = bytearray()
    key_len = len(encryption_key)
    data_bytes = data.encode('utf-8')
    for i, byte in enumerate(data_bytes):
        encrypted_data.append(byte ^ encryption_key[i % key_len])

    try:
        with open(filename, "wb") as f:
            f.write(bytes(encrypted_data))
    except Exception as e:
        print(f"Error writing to file: {e}")


def retrieve_sensitive_data(filename: str, encryption_key: bytes) -> str:
    """
    Retrieves and decrypts sensitive data from a file.

    This is a placeholder.  In a real application, use a robust encryption library
    like cryptography.io's Fernet or similar.  This example uses a very basic
    (and insecure) XOR encryption for demonstration purposes only.  DO NOT USE THIS IN PRODUCTION.

    :param filename: The name of the file to retrieve the encrypted data from.
    :param encryption_key: The encryption key (bytes).
    :return: The decrypted data.
    """
    # 10. Preconditions: 1. The code unit handles sensitive information
    # Guidelines: The code unit should store sensitive information (passwords; keys; credentials etc.) in a strongly protected encrypted configuration file or database with restricted access

    # THIS IS INSECURE XOR ENCRYPTION.  DO NOT USE IN PRODUCTION.
    try:
        with open(filename, "rb") as f:
            encrypted_data = bytearray(f.read())
    except FileNotFoundError:
        print("File not found.")
        return None
    except Exception as e:
        print(f"Error reading file: {e}")
        return None

    decrypted_data = bytearray()
    key_len = len(encryption_key)
    for i, byte in enumerate(encrypted_data):
        decrypted_data.append(byte ^ encryption_key[i % key_len])

    return decrypted_data.decode('utf-8')


# Example Usage (Illustrative - Replace with Secure Practices)
if __name__ == '__main__':
    # Example of generating a fingerprint
    key = secrets.token_bytes(32)  # Generate a random key
    iv = secrets.token_bytes(16)  # Generate a random IV
    fingerprint = generate_fingerprint(key, iv)
    print(f"Fingerprint: {fingerprint}")

    # Example of password hashing and verification
    password = "my_secret_password"
    salt, password_hash = hash_password(password)
    print(f"Salt: {salt.hex()}")
    print(f"Password Hash: {password_hash.decode('utf-8')}")

    is_valid = verify_hashed_password(password, salt, password_hash)
    print(f"Password valid: {is_valid}")

    # Example of key derivation
    derived_key = generate_key("another_secret_password")
    print(f"Derived Key: {derived_key.hex()}")

    # Example of storing sensitive data (INSECURE - REPLACE WITH PROPER ENCRYPTION)
    sensitive_data = "my_username:my_real_secret_password"
    encryption_key = secrets.token_bytes(32)  # Generate a random encryption key
    store_sensitive_data(sensitive_data, "sensitive.enc", encryption_key)
    retrieved_data = retrieve_sensitive_data("sensitive.enc", encryption_key)
    print(f"Retrieved Data: {retrieved_data}")

    # Example of password verification with PBKDF2HMAC
    password_to_verify = "another_secret_password"
    stored_salt = os.urandom(16) # In a real application, this would be retrieved from storage
    stored_key = generate_key(password_to_verify) # In a real application, this would be retrieved from storage
    is_password_correct = verify_password(password_to_verify, stored_key, stored_salt)
    print(f"Password verification with PBKDF2HMAC: {is_password_correct}")

