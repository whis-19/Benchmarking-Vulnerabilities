import os
import stat
import secrets
import base64
import getpass  # For secure password entry
import json
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import logging
import configparser  # For reading configuration files
import zxcvbn  # For password strength estimation

# --- Security Configuration (Loaded from config.ini) ---
config = configparser.ConfigParser()
config.read('config.ini')

ALLOWED_FILE_LOCATIONS = json.loads(config['security']['allowed_file_locations'])  # Load as list
ALLOWED_FILE_EXTENSIONS = json.loads(config['security']['allowed_file_extensions'])
SECRET_FILE_NAME = config['security']['secret_file_name']
SALT_LENGTH = int(config['security']['salt_length'])
PBKDF2_ITERATIONS = int(config['security']['pbkdf2_iterations'])
MIN_PASSWORD_LENGTH = int(config['security']['min_password_length'])

# --- Logging Configuration ---
logging.basicConfig(filename='security.log', level=logging.ERROR)

# --- Password Strength Estimator ---
password_evaluator = zxcvbn.ZXCVBN()


# --- Helper Functions ---

def is_path_safe(file_path, allowed_locations, allowed_extensions):
    """
    Validates the file path against path traversal attacks, allowed locations, and extensions.
    """
    abs_path = os.path.abspath(os.path.realpath(file_path))

    # Use commonpath to prevent symlink attacks
    try:
        common_path = os.path.commonpath([os.path.abspath(os.path.realpath(loc)) for loc in allowed_locations] + [abs_path])
        if common_path not in [os.path.abspath(os.path.realpath(loc)) for loc in allowed_locations]:
            logging.error(f"Path traversal attempt: {file_path}")
            return False
    except ValueError as e:
        logging.error(f"Path traversal attempt: {file_path} - No common path with allowed locations. Configuration error? {e}")  # More specific logging
        return False

    file_extension = os.path.splitext(abs_path)[1]

    if file_extension not in allowed_extensions:
        logging.error(f"Invalid file extension: {file_extension}")
        return False

    return True


def generate_salt(length):
    """Generates a cryptographically secure random salt."""
    return secrets.token_bytes(length)


def derive_key(password, salt, iterations):
    """Derives a key from the password and salt using PBKDF2HMAC."""
    password_bytes = password.encode('utf-8')
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # Key length for Fernet
        salt=salt,
        iterations=iterations,  # Use configurable iterations
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password_bytes))


def encrypt_data(data, key):
    """Encrypts the data using Fernet."""
    f = Fernet(key)
    return f.encrypt(data.encode('utf-8'))


def decrypt_data(encrypted_data, key):
    """Decrypts the data using Fernet."""
    f = Fernet(key)
    return f.decrypt(encrypted_data).decode('utf-8')


def create_and_write_secure_file(file_path, data, password):
    """
    Creates a file, encrypts the data, writes it to the file, and sets restrictive permissions.
    """
    if not is_path_safe(file_path, ALLOWED_FILE_LOCATIONS, ALLOWED_FILE_EXTENSIONS):
        return

    try:
        # Generate a salt
        salt = generate_salt(SALT_LENGTH)

        # Derive the encryption key from the password and salt
        key = derive_key(password, salt, PBKDF2_ITERATIONS)

        # Encrypt the data
        encrypted_data = encrypt_data(data, key)

        # Store salt and encrypted data in JSON format
        file_content = {
            "salt": base64.b64encode(salt).decode('utf-8'),
            "encrypted_data": base64.b64encode(encrypted_data).decode('utf-8'),
            "iterations": PBKDF2_ITERATIONS  # Store iteration count
        }

        # Atomically write the file
        temp_file_path = file_path + ".tmp"
        with open(temp_file_path, "w") as f:  # Use text mode for JSON
            json.dump(file_content, f)
        os.replace(temp_file_path, file_path)  # Atomic rename

        # Set restrictive file permissions (read/write for owner only)
        os.chmod(file_path, stat.S_IRUSR | stat.S_IWUSR)

        print(f"File '{file_path}' created and written successfully with encrypted data.")

    except (OSError, json.JSONDecodeError) as e:  # More specific exception handling
        logging.error(f"Error creating or writing to file: {e}")
        print(f"Error creating or writing to file: {e}")


def read_and_decrypt_secure_file(file_path, password):
    """Reads the encrypted data from the file, decrypts it, and returns the data."""
    if not is_path_safe(file_path, ALLOWED_FILE_LOCATIONS, ALLOWED_FILE_EXTENSIONS):
        return None

    try:
        with open(file_path, "r") as f:  # Use text mode for JSON
            file_content = json.load(f)

        salt = base64.b64decode(file_content["salt"])
        encrypted_data = base64.b64decode(file_content["encrypted_data"])
        iterations = file_content.get("iterations", 390000)  # Get iterations, default to old value

        # Derive the key from the password and salt
        key = derive_key(password, salt, iterations)

        # Decrypt the data
        decrypted_data = decrypt_data(encrypted_data, key)

        return decrypted_data

    except (FileNotFoundError, OSError, json.JSONDecodeError) as e:  # More specific exception handling
        logging.error(f"Error reading or decrypting file: {e}")
        print(f"Error reading or decrypting file: {e}")
        return None


def print_file_permissions(file_path):
    """Prints the file permissions in octal format."""
    try:
        permissions = stat.filemode(os.stat(file_path).st_mode)
        print(f"File permissions for '{file_path}': {permissions}")
    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found.")
    except Exception as e:
        print(f"Error getting file permissions: {e}")


def get_strong_password():
    """Prompts the user for a password and enforces complexity requirements."""
    while True:
        password = getpass.getpass("Enter password: ")
        if len(password) < MIN_PASSWORD_LENGTH:
            print(f"Password must be at least {MIN_PASSWORD_LENGTH} characters long.")
            continue

        # Evaluate password strength
        strength = password_evaluator.password_strength(password)
        if strength['score'] < 3:  # Adjust score threshold as needed
            print("Password is too weak.  Consider using a longer password with a mix of characters.")
            print(f"Suggestions: {strength['feedback']['suggestions']}")
            continue

        # Add more complexity checks here if needed (e.g., regex for character types)

        password_confirmation = getpass.getpass("Confirm password: ")
        if password != password_confirmation:
            print("Passwords do not match.")
            continue

        return password


# --- Main Execution ---

if __name__ == "__main__":

    # Example config.ini file
    # [security]
    # allowed_file_locations = ["."]
    # allowed_file_extensions = [".txt"]
    # secret_file_name = "secret.txt"
    # salt_length = 16
    # pbkdf2_iterations = 390000
    # min_password_length = 12

    file_path = SECRET_FILE_NAME
    data_to_write = "This is some sensitive data to encrypt."

    # Get password from user
    password = get_strong_password()

    # Create and write the secure file
    create_and_write_secure_file(file_path, data_to_write, password)

    # Print the file permissions
    print_file_permissions(file_path)

    # Example of reading and decrypting the file
    decrypted_data = read_and_decrypt_secure_file(file_path, password)
    if decrypted_data:
        print(f"Decrypted data: {decrypted_data}")

