import os
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.exceptions import InvalidTag
import base64
import logging
import sqlite3  # Import SQLite
import secrets  # For generating secure random numbers

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- Configuration ---
DATABASE_FILE = "credentials.db"
PBKDF2_ITERATIONS = 150000  # Increased iteration count
USERNAME_MIN_LENGTH = 3
PASSWORD_MIN_LENGTH = 8

# --- Key Derivation and Storage (Database Version) ---

def store_credentials(username, password, db_file=DATABASE_FILE):
    """Stores the username, salt, and password hash in a SQLite database."""

    # Input Validation
    if not isinstance(username, str) or len(username) < USERNAME_MIN_LENGTH:
        logging.error(f"Invalid username: Must be a string with at least {USERNAME_MIN_LENGTH} characters.")
        return False
    if not isinstance(password, str) or len(password) < PASSWORD_MIN_LENGTH:
        logging.error(f"Invalid password: Must be a string with at least {PASSWORD_MIN_LENGTH} characters.")
        return False

    salt = generate_salt()
    hashed_password = hash_password(password, salt)

    encoded_salt = base64.b64encode(salt).decode('utf-8')
    encoded_hash = base64.b64encode(hashed_password).decode('utf-8')

    try:
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()

        # Create table if it doesn't exist
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                salt TEXT NOT NULL,
                hash TEXT NOT NULL
            )
        """)

        # Insert or replace the user's credentials
        cursor.execute("INSERT OR REPLACE INTO users (username, salt, hash) VALUES (?, ?, ?)",
                       (username, encoded_salt, encoded_hash))

        conn.commit()
        conn.close()
        logging.info(f"Credentials stored successfully for user: {username}")
        return True
    except sqlite3.Error as e:
        logging.error(f"Error storing credentials in database: {e}")
        if conn:
            conn.rollback()  # Rollback changes in case of error
            conn.close()
        return False

def load_credentials(username, db_file=DATABASE_FILE):
    """Loads credentials from the SQLite database."""
    try:
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()

        cursor.execute("SELECT salt, hash FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()

        conn.close()

        if result:
            encoded_salt, encoded_hash = result
            salt = base64.b64decode(encoded_salt.encode('utf-8'))
            stored_hash = base64.b64decode(encoded_hash.encode('utf-8'))
            return salt, stored_hash
        else:
            logging.warning(f"User not found: {username}")
            return None, None
    except sqlite3.Error as e:
        logging.error(f"Error loading credentials from database: {e}")
        return None, None

# --- Password Hashing ---

def generate_salt():
    """Generates a random salt for password hashing."""
    return os.urandom(16)

def hash_password(password, salt):
    """Hashes the password using PBKDF2HMAC with the provided salt."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # Key length
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
        backend=default_backend()
    )
    hashed_password = kdf.derive(password.encode('utf-8'))
    return hashed_password

def verify_password(password, salt, stored_hash):
    """Verifies the password against the stored hash and salt."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
        backend=default_backend()
    )
    try:
        kdf.verify(password.encode('utf-8'), stored_hash)
        return True
    except InvalidTag:
        logging.warning("Authentication failed: Invalid tag (possible password mismatch).")
        return False
    except Exception as e:  # Catch other potential exceptions
        logging.error(f"Error during password verification: {e}")
        return False

# --- Encryption (AES-GCM) ---

def generate_encryption_key():
    """Generates a random encryption key."""
    return os.urandom(32)  # 256-bit key

def encrypt_data(data, key):
    """Encrypts data using AES-GCM."""
    iv = os.urandom(16)  # Initialization Vector (128 bits)
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data.encode('utf-8')) + encryptor.finalize()
    return iv, ciphertext, encryptor.tag  # Return IV, ciphertext, and authentication tag

def decrypt_data(iv, ciphertext, key, tag):
    """Decrypts data using AES-GCM."""
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    try:
        decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
        return decrypted_data.decode('utf-8')
    except Exception as e:
        logging.error(f"Decryption error: {e}")
        return None

# --- Example Usage ---

if __name__ == '__main__':
    # --- Authentication Example ---
    username = "testuser"
    password = "secure_password123"

    # Store credentials (in a real app, this would be during user registration)
    if store_credentials(username, password):
        print("Credentials stored successfully.")

    # Load credentials (during login)
    salt, stored_hash = load_credentials(username)

    if salt and stored_hash:
        # Verify password
        login_password = "secure_password123"  # Correct password
        if verify_password(login_password, salt, stored_hash):
            print("Authentication successful!")
        else:
            print("Authentication failed.")

        login_password = "wrong_password"  # Incorrect password
        if verify_password(login_password, salt, stored_hash):
            print("Authentication successful!")
        else:
            print("Authentication failed.")
    else:
        print("Failed to load credentials.")

    # --- Encryption Example ---
    data_to_encrypt = "This is some sensitive data."
    encryption_key = generate_encryption_key()

    iv, ciphertext, tag = encrypt_data(data_to_encrypt, encryption_key)

    decrypted_data = decrypt_data(iv, ciphertext, encryption_key, tag)

    if decrypted_data:
        print(f"Original data: {data_to_encrypt}")
        print(f"Decrypted data: {decrypted_data}")
    else:
        print("Decryption failed.")

