import secrets
import string
import os
import hashlib
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import time

# --- Configuration (Ideally, load from an encrypted file) ---
# This section simulates loading configuration from a secure source.
# In a real application, this would involve reading from an encrypted file
# or a secure database.  DO NOT HARDCODE SENSITIVE DATA IN YOUR CODE.

# Example:  Load the encryption key from an environment variable or a file.
# encryption_key = os.environ.get("ENCRYPTION_KEY")
# if not encryption_key:
#     # Handle the case where the key is not found (e.g., generate a new one, but store it securely)
#     encryption_key = Fernet.generate_key()
#     # Securely store the key (e.g., in a password manager, encrypted file, or KMS)
#     print("WARNING: No encryption key found.  Generated a new one.  Store it securely!")
#     # In a real application, you would *never* print the key.
#
# # Example of loading from a file (replace with your actual file path)
# # with open("encryption_key.key", "rb") as key_file:
# #     encryption_key = key_file.read()

# For demonstration purposes, we'll generate a key here, but this is NOT secure for production.
# In a real application, the key should be generated once and stored securely.
encryption_key = Fernet.generate_key()

# --- End Configuration ---


def generate_salt():
    """Generates a random salt for password hashing."""
    return secrets.token_hex(16)  # 16 bytes = 32 hex characters


def hash_password(password, salt):
    """Hashes the password using a strong one-way hash with a salt."""
    # Use a strong key derivation function (KDF) like PBKDF2HMAC
    password_bytes = password.encode('utf-8')
    salt_bytes = salt.encode('utf-8')

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # Key length (in bytes)
        salt=salt_bytes,
        iterations=480000,  # Number of iterations (adjust for security/performance)
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password_bytes))
    return key.decode('utf-8')


def generate_password(length=12):  # Increased default length
    """Generates a cryptographically secure random password."""
    alphabet = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(alphabet) for i in range(length))


def generate_temporary_password(expiration_time=60):  # Expiration in seconds
    """Generates a temporary password that expires after a specified time."""
    password = generate_password()
    salt = generate_salt()
    hashed_password = hash_password(password, salt)

    # Store the hashed password, salt, and expiration time in memory.
    # In a real application, this would be stored in a secure session or cache.
    temporary_passwords[hashed_password] = {
        'salt': salt,
        'expiration': time.time() + expiration_time
    }

    return password, hashed_password  # Return both the plain text and hashed password


def validate_temporary_password(password, hashed_password):
    """Validates a temporary password against the stored hash and expiration time."""
    if hashed_password not in temporary_passwords:
        return False

    password_data = temporary_passwords[hashed_password]
    salt = password_data['salt']
    expiration = password_data['expiration']

    if time.time() > expiration:
        # Password has expired
        del temporary_passwords[hashed_password]  # Remove expired password
        return False

    # Hash the provided password with the stored salt and compare
    hashed_input_password = hash_password(password, salt)
    if hashed_input_password == hashed_password:
        del temporary_passwords[hashed_password]  # Remove after successful validation
        return True
    else:
        return False


def encrypt_sensitive_data(data):
    """Encrypts sensitive data using Fernet encryption."""
    f = Fernet(encryption_key)
    encrypted_data = f.encrypt(data.encode('utf-8'))
    return encrypted_data


def decrypt_sensitive_data(encrypted_data):
    """Decrypts sensitive data using Fernet encryption."""
    f = Fernet(encryption_key)
    decrypted_data = f.decrypt(encrypted_data).decode('utf-8')
    return decrypted_data


# --- Example Usage (Illustrative) ---

# In-memory storage for temporary passwords (DO NOT USE IN PRODUCTION)
temporary_passwords = {}

def main():
    # 1. Generate a strong password
    new_password = generate_password()
    print(f"Generated password: {new_password}")

    # 2. Hash the password with a salt
    salt = generate_salt()
    hashed_password = hash_password(new_password, salt)
    print(f"Salt: {salt}")
    print(f"Hashed password: {hashed_password}")

    # 3. Store the salt and hashed password securely (e.g., in a database)
    #    - In a real application, you would store the salt and hashed password
    #      in a database column.

    # 4. Verify the password
    #    - When the user tries to log in, retrieve the salt from the database
    #      and hash the entered password with the salt.  Compare the result
    #      to the stored hashed password.

    # Example of temporary password generation and validation
    temp_password, temp_hashed_password = generate_temporary_password(expiration_time=10)
    print(f"Temporary password: {temp_password}")
    print(f"Temporary hashed password: {temp_hashed_password}")

    # Simulate user entering the temporary password
    time.sleep(2)  # Wait a few seconds
    is_valid = validate_temporary_password(temp_password, temp_hashed_password)
    print(f"Is temporary password valid? {is_valid}")

    time.sleep(10)  # Wait for the password to expire
    is_valid = validate_temporary_password(temp_password, temp_hashed_password)
    print(f"Is temporary password valid after expiration? {is_valid}")

    # Example of encrypting and decrypting sensitive data
    sensitive_data = "My secret API key"
    encrypted_data = encrypt_sensitive_data(sensitive_data)
    print(f"Encrypted data: {encrypted_data}")

    decrypted_data = decrypt_sensitive_data(encrypted_data)
    print(f"Decrypted data: {decrypted_data}")

if __name__ == "__main__":
    main()

