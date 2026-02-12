import os
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.exceptions import InvalidTag
import base64

# --- Key Derivation and Encryption Helper Functions ---

def generate_salt():
    """Generates a random salt for key derivation."""
    return os.urandom(16)

def derive_key(password, salt):
    """Derives a key from a password and salt using PBKDF2HMAC."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # Key length (e.g., 32 bytes for AES-256)
        salt=salt,
        iterations=100000,  # Adjust iteration count for security
        backend=default_backend()
    )
    return kdf.derive(password)

def encrypt(data, key, iv):
    """Encrypts data using AES-CBC with the given key and IV."""
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(padded_data) + encryptor.finalize()

def decrypt(ciphertext, key, iv):
    """Decrypts data using AES-CBC with the given key and IV."""
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_padded_data = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    return unpadder.update(decrypted_padded_data) + unpadder.finalize()


# --- Secure Key Handling and Storage ---

def store_encrypted_key(key_to_protect, password, config_file="config.enc"):
    """
    Encrypts a key using a password-derived key and stores it securely.

    Args:
        key_to_protect: The key (bytes) to be encrypted.
        password: The password (bytes) used to derive the encryption key.
        config_file: The file to store the encrypted key, salt, and IV.
    """

    salt = generate_salt()
    key = derive_key(password, salt)
    iv = os.urandom(16)  # Initialization Vector

    encrypted_key = encrypt(key_to_protect, key, iv)

    # Store encrypted key, salt, and IV in the config file.  Base64 encode for safe storage.
    with open(config_file, "wb") as f:
        f.write(b"salt=" + base64.b64encode(salt) + b"\n")
        f.write(b"iv=" + base64.b64encode(iv) + b"\n")
        f.write(b"encrypted_key=" + base64.b64encode(encrypted_key) + b"\n")

    # IMPORTANT:  Set appropriate file permissions on the config_file
    # to restrict access to the user/process that needs to access the key.
    # Example (Linux/Unix): os.chmod(config_file, 0o600)  # Read/write for owner only


def retrieve_decrypted_key(password, config_file="config.enc"):
    """
    Retrieves and decrypts the key from the configuration file.

    Args:
        password: The password (bytes) used to derive the decryption key.
        config_file: The file containing the encrypted key, salt, and IV.

    Returns:
        The decrypted key (bytes), or None if decryption fails.
    """
    try:
        with open(config_file, "rb") as f:
            config_data = f.readlines()

        salt = base64.b64decode(config_data[0].split(b"=")[1].strip())
        iv = base64.b64decode(config_data[1].split(b"=")[1].strip())
        encrypted_key = base64.b64decode(config_data[2].split(b"=")[1].strip())

        key = derive_key(password, salt)
        decrypted_key = decrypt(encrypted_key, key, iv)
        return decrypted_key

    except (FileNotFoundError, IndexError, ValueError, InvalidTag) as e:
        print(f"Error retrieving/decrypting key: {e}")
        return None


# --- Password Hashing ---

def hash_password(password):
    """Hashes a password using PBKDF2HMAC."""
    salt = generate_salt()
    hashed_password = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    ).derive(password)
    return salt, hashed_password

def verify_password(password, salt, hashed_password):
    """Verifies a password against a stored hash."""
    try:
        PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        ).verify(password, hashed_password)
        return True
    except InvalidTag:
        return False


# --- Example Usage (Illustrative) ---

if __name__ == "__main__":
    # 1. Key Generation and Storage
    my_secret_key = os.urandom(32)  # Example: Generate a 32-byte AES key
    admin_password = b"StrongAdminPassword123!"  # Replace with a strong, randomly generated password
    store_encrypted_key(my_secret_key, admin_password)
    print("Key encrypted and stored securely.")

    # 2. Key Retrieval and Decryption
    retrieved_key = retrieve_decrypted_key(admin_password)
    if retrieved_key:
        print("Key retrieved and decrypted successfully.")
        assert retrieved_key == my_secret_key, "Decrypted key does not match original!"
    else:
        print("Failed to retrieve/decrypt the key.")

    # 3. Password Hashing and Verification
    user_password = b"UserPassword"
    salt, hashed = hash_password(user_password)
    print(f"Salt: {salt.hex()}")
    print(f"Hashed Password: {hashed.hex()}")

    is_valid = verify_password(user_password, salt, hashed)
    print(f"Password verification: {is_valid}")

    is_valid = verify_password(b"WrongPassword", salt, hashed)
    print(f"Password verification (wrong password): {is_valid}")


# --- Important Considerations ---

# * **Password Management:**  The `admin_password` used to encrypt the key MUST be managed securely.  It should be:
#     *  Strong and randomly generated.
#     *  Stored separately from the encrypted key (e.g., in a secure password manager, hardware security module, or managed by a system administrator).
#     *  Rotated periodically.
# * **Configuration File Permissions:**  The `config.enc` file MUST have restricted permissions (e.g., 0600 on Linux/Unix) to prevent unauthorized access.
# * **Error Handling:**  The code includes basic error handling, but you should implement more robust error handling and logging in a production environment.
# * **Key Rotation:** Implement a key rotation strategy to periodically generate new keys and re-encrypt data.
# * **HSM Integration:** For highly sensitive applications, consider using a Hardware Security Module (HSM) to store and manage encryption keys.
# * **Regular Security Audits:**  Conduct regular security audits of your code and infrastructure to identify and address potential vulnerabilities.
# * **Never log sensitive information:**  Avoid logging the password, salt, key, or encrypted key.  Log only necessary information for debugging purposes.
# * **Input Validation:**  Validate all user inputs to prevent injection attacks.
# * **Dependencies:**  Keep your dependencies up to date to patch security vulnerabilities.

