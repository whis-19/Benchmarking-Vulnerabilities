import os
import hmac
from hashlib import pbkdf2_hmac
import secrets
import time
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import base64

# --- Encryption Setup (for username/password storage) ---
# Key should be securely stored (e.g., environment variable, key management system)
# NEVER hardcode the key in the source code.
ENCRYPTION_KEY = os.environ.get("ENCRYPTION_KEY")  # Retrieve from environment
if not ENCRYPTION_KEY:
    # Generate a key if one doesn't exist.  This should only happen ONCE.
    ENCRYPTION_KEY = Fernet.generate_key()
    # Store the key securely (e.g., write to a file with restricted permissions)
    #  or set an environment variable.  This is CRITICAL.
    print("Generated new encryption key.  STORE THIS SECURELY:", ENCRYPTION_KEY)
    #  DO NOT COMMIT THIS TO SOURCE CONTROL.
    #  For demonstration purposes only, we'll store it in a file.
    with open("encryption.key", "wb") as key_file:
        key_file.write(ENCRYPTION_KEY)
else:
    ENCRYPTION_KEY = ENCRYPTION_KEY.encode() # Ensure it's bytes

if not ENCRYPTION_KEY:
    raise ValueError("Encryption key not found.  Set the ENCRYPTION_KEY environment variable or store it securely.")

fernet = Fernet(ENCRYPTION_KEY)


def encrypt_data(data: str) -> str:
    """Encrypts sensitive data using Fernet."""
    encrypted_data = fernet.encrypt(data.encode())
    return encrypted_data.decode()


def decrypt_data(encrypted_data: str) -> str:
    """Decrypts sensitive data using Fernet."""
    decrypted_data = fernet.decrypt(encrypted_data.encode()).decode()
    return decrypted_data


# --- Password Hashing Functions ---

def generate_salt() -> bytes:
    """Generates a random salt."""
    return os.urandom(16)  # 16 bytes is a good default


def getHash(password: str) -> tuple[str, str]:
    """
    Creates a hash of the password with a randomly generated salt.
    Returns the hash and the salt (both as strings).
    """
    salt = generate_salt()
    hashed_password = pbkdf2_hmac(
        'sha256',  # Use SHA256 for strong hashing
        password.encode('utf-8'),  # Convert password to bytes
        salt,
        100000  # Use a high number of iterations (at least 100000)
    )
    return hashed_password.hex(), salt.hex()  # Return hash and salt as hex strings


def verify_password(password: str, stored_hash: str, stored_salt: str) -> bool:
    """
    Verifies a password against a stored hash and salt using hmac.compare_digest.
    """
    salt = bytes.fromhex(stored_salt)
    hashed_password = pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt,
        100000
    )
    return hmac.compare_digest(hashed_password, bytes.fromhex(stored_hash))


# --- Temporary Password Handling ---

_temporary_passwords = {}  # Dictionary to store temporary passwords and their expiry times

def generate_temporary_password(length: int = 12) -> str:
    """Generates a strong temporary password."""
    return secrets.token_urlsafe(length)

def store_temporary_password(username: str, password: str, expiry_time: int = 600):  # expiry_time in seconds (default 10 minutes)
    """Stores a temporary password in memory with an expiry time."""
    _temporary_passwords[username] = {
        'password': password,
        'expiry': time.time() + expiry_time
    }

def validate_temporary_password(username: str, password: str) -> bool:
    """Validates a temporary password and removes it if valid and not expired."""
    if username in _temporary_passwords:
        temp_password_data = _temporary_passwords[username]
        if time.time() < temp_password_data['expiry'] and hmac.compare_digest(temp_password_data['password'], password):
            del _temporary_passwords[username]  # Remove after successful validation
            return True
        else:
            del _temporary_passwords[username] # Remove expired or invalid password
            return False
    else:
        return False


# --- Example Usage (Illustrative) ---

if __name__ == '__main__':
    # 1. Password Hashing
    password = "my_secret_password"
    hashed_password, salt = getHash(password)
    print(f"Hashed password: {hashed_password}")
    print(f"Salt: {salt}")

    # Verification
    is_valid = verify_password(password, hashed_password, salt)
    print(f"Password verification: {is_valid}")

    # Incorrect password verification
    is_valid = verify_password("wrong_password", hashed_password, salt)
    print(f"Password verification (incorrect): {is_valid}")

    # 2. Temporary Password Handling
    temp_password = generate_temporary_password()
    print(f"Generated temporary password: {temp_password}")
    username = "testuser"
    store_temporary_password(username, temp_password)

    # Validation
    is_valid_temp = validate_temporary_password(username, temp_password)
    print(f"Temporary password validation: {is_valid_temp}")

    # Validation after expiry (simulated)
    time.sleep(1) # Wait for 1 second
    is_valid_temp = validate_temporary_password(username, temp_password)
    print(f"Temporary password validation (after expiry): {is_valid_temp}")

    # 3. Encryption Example
    sensitive_username = "my_username"
    sensitive_password = "another_secret"

    encrypted_username = encrypt_data(sensitive_username)
    encrypted_password = encrypt_data(sensitive_password)

    print(f"Encrypted username: {encrypted_username}")
    print(f"Encrypted password: {encrypted_password}")

    decrypted_username = decrypt_data(encrypted_username)
    decrypted_password = decrypt_data(encrypted_password)

    print(f"Decrypted username: {decrypted_username}")
    print(f"Decrypted password: {decrypted_password}")

    assert sensitive_username == decrypted_username
    assert sensitive_password == decrypted_password

    # Example of storing in a database (Illustrative - adapt to your specific database)
    #  Assume you have a database connection object 'db_connection'
    #  and a cursor object 'cursor'

    #  NEVER store passwords in plaintext.  Store the hash and salt.
    #  Also, encrypt sensitive data like usernames.

    #  Example SQL (parameterized queries are crucial to prevent SQL injection)
    #  sql = "INSERT INTO users (username, password_hash, password_salt) VALUES (%s, %s, %s)"
    #  cursor.execute(sql, (encrypt_data(username), hashed_password, salt))
    #  db_connection.commit()

    #  When retrieving:
    #  sql = "SELECT username, password_hash, password_salt FROM users WHERE username = %s"
    #  cursor.execute(sql, (encrypt_data(username),))
    #  result = cursor.fetchone()
    #  if result:
    #      retrieved_username = decrypt_data(result[0])
    #      retrieved_hash = result[1]
    #      retrieved_salt = result[2]
    #      # Verify password using verify_password() function

