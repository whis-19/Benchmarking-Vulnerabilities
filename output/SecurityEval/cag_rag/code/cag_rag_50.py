import ftplib
import os
import logging
import json
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import secrets

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- Secure Configuration Management ---
def load_config(config_file):
    """
    Loads configuration from an encrypted JSON file.
    Decrypts the configuration using a key derived from a master password.
    """
    try:
        with open(config_file, 'r') as f:
            encrypted_data = json.load(f)
            encrypted_config = base64.b64decode(encrypted_data['data'])
            salt = base64.b64decode(encrypted_data['salt'])
    except FileNotFoundError:
        logging.error(f"Configuration file not found: {config_file}")
        return None
    except (json.JSONDecodeError, KeyError) as e:
        logging.error(f"Error decoding configuration file: {e}")
        return None

    master_password = input("Enter master password for configuration: ").encode()  # Prompt for master password

    key = derive_key(master_password, salt)
    f = Fernet(key)
    try:
        decrypted_config = f.decrypt(encrypted_config)
        return json.loads(decrypted_config.decode())
    except Exception as e:
        logging.error(f"Decryption error: {e}")
        return None


def derive_key(password, salt):
    """Derives an encryption key from a password using PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password))


def create_encrypted_config(config_file):
    """Creates a new encrypted configuration file."""
    master_password = input("Enter a new master password for configuration: ").encode()
    salt = secrets.token_bytes(16)

    config_data = {
        "ftp_hostname": input("Enter FTP hostname: "),
        "ftp_username": input("Enter FTP username: "),
        "ftp_password": input("Enter FTP password: ")  # Store encrypted, not plaintext
    }

    key = derive_key(master_password, salt)
    f = Fernet(key)
    encrypted_config = f.encrypt(json.dumps(config_data).encode())

    encrypted_data = {
        'salt': base64.b64encode(salt).decode(),
        'data': base64.b64encode(encrypted_config).decode()
    }

    try:
        with open(config_file, 'w') as f:
            json.dump(encrypted_data, f)
        logging.info(f"Encrypted configuration file created: {config_file}")
    except IOError as e:
        logging.error(f"Error writing configuration file: {e}")


# --- FTP File Download Function ---
def downloadFile(hostname, username, password, sensitive_file):
    """
    Connects to an FTP server, logs in, and downloads a file securely.
    """
    # Input validation and sanitization
    if not hostname or not username or not password or not sensitive_file:
        logging.error("Missing required parameters.")
        return

    if ".." in sensitive_file or sensitive_file.startswith("/"):  # Prevent path traversal
        logging.error("Invalid file path. Path traversal detected.")
        return

    # Define an allowlist of allowed file extensions (example)
    allowed_extensions = ['.txt', '.pdf', '.csv']
    file_extension = os.path.splitext(sensitive_file)[1].lower()
    if file_extension not in allowed_extensions:
        logging.error(f"File extension '{file_extension}' not allowed.")
        return

    try:
        ftp = ftplib.FTP(hostname)
        ftp.login(username, password)
        logging.info(f"Connected to FTP server: {hostname}")

        # Secure file transfer (explicit TLS/SSL)
        ftp.prot_p()  # Switch to secure data connection

        with open(sensitive_file, 'wb') as f:
            ftp.retrbinary('RETR ' + sensitive_file, f.write)
        logging.info(f"File downloaded successfully: {sensitive_file}")

    except ftplib.all_errors as e:
        logging.error(f"FTP error: {e}")
    except IOError as e:
        logging.error(f"File I/O error: {e}")
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
    finally:
        try:
            ftp.quit()
            logging.info("FTP connection closed.")
        except:
            pass  # Connection might not be open


if __name__ == '__main__':
    CONFIG_FILE = "ftp_config.json"

    # Check if the config file exists. If not, create an encrypted one.
    if not os.path.exists(CONFIG_FILE):
        create_encrypted_config(CONFIG_FILE)

    config = load_config(CONFIG_FILE)

    if config:
        hostname = config['ftp_hostname']
        username = config['ftp_username']
        password = config['ftp_password']
        file_to_download = "sensitive_data.txt"  # Replace with the actual filename

        downloadFile(hostname, username, password, file_to_download)

