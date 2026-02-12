import os
import stat
import secrets
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag
import logging
import getpass  # Import getpass here

# --- Security Configuration ---
ALLOWED_FILE_LOCATIONS = ["/path/to/secure/directory"]  # Replace with a specific, secure directory
ALLOWED_FILE_EXTENSIONS = [".txt"]
FILE_NAME = "secret.txt"
FILE_PATH = os.path.join(ALLOWED_FILE_LOCATIONS[0], FILE_NAME)  # Construct the full file path

# --- Cryptographic Configuration ---
SALT_LENGTH = 16  # Length of the salt in bytes
ITERATIONS = 500000  # Number of iterations for PBKDF2 - INCREASED
KEY_LENGTH = 32  # Length of the derived key in bytes
NONCE_LENGTH = 16 # Length of the nonce for AES-GCM

# --- Logging Configuration ---
LOG_FILE = "/path/to/secure/log/file.log"  # Replace with a secure log file location
logging.basicConfig(filename=LOG_FILE, level=logging.ERROR, format='%(asctime)s - %(levelname)s - %(message)s')

def get_password_from_user():
    """
    Gets the password from the user securely using getpass.
    """
    try:
        password = getpass.getpass("Enter password: ")
        return password.encode('utf-8')  # Encode to bytes
    except KeyboardInterrupt:
        logging.error("Password entry cancelled by user.")
        return None
    except Exception as e:
        logging.exception("Error getting password:")  # Log the full exception
        return None

def derive_key(password, salt):
    """
    Derives a key from the password using PBKDF2HMAC.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LENGTH,
        salt=salt,
        iterations=ITERATIONS,
        backend=default_backend()
    )
    return kdf.derive(password)

def encrypt_data(data, key):
    """
    Encrypts the data using AES-GCM for authenticated encryption.
    """
    # Generate a random nonce (IV)
    nonce = secrets.token_bytes(NONCE_LENGTH)

    # Create an AES-GCM cipher object
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()

    # Encrypt the data
    ciphertext = encryptor.update(data) + encryptor.finalize()

    # Return the nonce and the ciphertext
    return nonce, ciphertext, encryptor.tag # Return the nonce, ciphertext, and authentication tag

def decrypt_data(nonce, ciphertext, key, tag):
    """
    Decrypts the data using AES-GCM.
    """
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    try:
        return decryptor.update(ciphertext) + decryptor.finalize()
    except InvalidTag:
        logging.error("Authentication failed: Data may have been tampered with.")
        return None  # Or raise a custom exception

def is_path_safe(file_path, allowed_locations, allowed_extensions):
    """
    Checks if the file path is within the allowed locations and has an allowed extension.
    """
    try:
        # Normalize the paths to prevent bypasses
        file_path = os.path.normpath(os.path.abspath(file_path))
        for location in allowed_locations:
            allowed_location = os.path.normpath(os.path.abspath(location))
            if file_path.startswith(allowed_location):
                if any(file_path.endswith(ext) for ext in allowed_extensions):
                    return True
        return False
    except Exception as e:
        # Log the error securely (don't print to console in production)
        logging.error(f"Error in is_path_safe: {e}")
        return False  # Treat errors as unsafe

def create_and_secure_file(file_path, data):
    """
    Creates a file, writes encrypted data to it, and sets restrictive permissions.
    """
    if not is_path_safe(file_path, ALLOWED_FILE_LOCATIONS, ALLOWED_FILE_EXTENSIONS):
        logging.error(f"Unsafe file path: {file_path}")
        return

    # Generate a random salt
    salt = secrets.token_bytes(SALT_LENGTH)

    # Get the password from the user (or a secure source)
    password = get_password_from_user()
    if password is None:
        logging.error("Failed to get password. Aborting file creation.")
        return

    # Derive the encryption key from the password and salt
    key = derive_key(password, salt)

    # Encrypt the data
    nonce, ciphertext, tag = encrypt_data(data.encode('utf-8'), key)

    # Base64 encode the encrypted data, salt, and nonce for storage
    encoded_ciphertext = base64.b64encode(ciphertext).decode('utf-8')
    encoded_salt = base64.b64encode(salt).decode('utf-8')
    encoded_nonce = base64.b64encode(nonce).decode('utf-8')
    encoded_tag = base64.b64encode(tag).decode('utf-8')

    # Store the salt, nonce, and encrypted data in *separate* files or locations
    salt_file_path = os.path.join(ALLOWED_FILE_LOCATIONS[0], "secret.salt")  # Example
    nonce_file_path = os.path.join(ALLOWED_FILE_LOCATIONS[0], "secret.nonce") # Example
    tag_file_path = os.path.join(ALLOWED_FILE_LOCATIONS[0], "secret.tag") # Example

    try:
        # Check if files exist and prompt for overwrite (example)
        if os.path.exists(file_path) or os.path.exists(salt_file_path) or os.path.exists(nonce_file_path) or os.path.exists(tag_file_path):
            overwrite = input("One or more files already exist. Overwrite? (y/n): ")
            if overwrite.lower() != 'y':
                logging.warning("File creation aborted by user.")
                return

        with open(file_path, "w") as f, open(salt_file_path, "wb") as sf, open(nonce_file_path, "wb") as nf, open(tag_file_path, "wb") as tf: # Open salt and nonce files in binary write mode
            sf.write(base64.b64decode(encoded_salt)) # Write salt to salt file
            nf.write(base64.b64decode(encoded_nonce)) # Write nonce to nonce file
            tf.write(base64.b64decode(encoded_tag)) # Write tag to tag file
            f.write(f"Data:{encoded_ciphertext}\n")  # Store the encrypted data

        # Set restrictive file permissions (read/write for owner only)
        os.chmod(file_path, stat.S_IRUSR | stat.S_IWUSR)
        os.chmod(salt_file_path, stat.S_IRUSR | stat.S_IWUSR) # Secure the salt file
        os.chmod(nonce_file_path, stat.S_IRUSR | stat.S_IWUSR) # Secure the nonce file
        os.chmod(tag_file_path, stat.S_IRUSR | stat.S_IWUSR) # Secure the tag file

        print(f"File '{file_path}' created and secured successfully.")

    except OSError as e:
        logging.exception(f"Error creating or securing file:") # Log the full exception

def main():
    # NEVER HARDCODE SENSITIVE DATA!
    data_to_encrypt = input("Enter data to encrypt: ") # Get data from user

    create_and_secure_file(FILE_PATH, data_to_encrypt)
    #print_file_permissions(FILE_PATH) # Removed because it's not really useful in this context

if __name__ == "__main__":
    main()

