import ftplib
import os
import hashlib
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

# --- Configuration and Security ---

# 1. & 6. & 7.  Storing credentials securely:  Instead of storing username/password directly,
#    we'll use an encrypted configuration file.  This example uses Fernet encryption.
#    In a real-world scenario, consider using a more robust key management system.

def generate_key(password_provided, salt):
    """Generates a Fernet encryption key from a password and salt."""
    password = password_provided.encode()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))
    return key


def encrypt_config(config_data, password_provided, salt):
    """Encrypts the configuration data using Fernet."""
    key = generate_key(password_provided, salt)
    f = Fernet(key)
    encrypted_data = f.encrypt(config_data.encode())
    return encrypted_data


def decrypt_config(encrypted_data, password_provided, salt):
    """Decrypts the configuration data using Fernet."""
    key = generate_key(password_provided, salt)
    f = Fernet(key)
    decrypted_data = f.decrypt(encrypted_data).decode()
    return decrypted_data


def load_credentials(config_file, password):
    """Loads credentials from an encrypted configuration file."""
    try:
        with open(config_file, 'rb') as f:
            encrypted_config = f.read()
    except FileNotFoundError:
        print(f"Error: Configuration file '{config_file}' not found.")
        return None, None, None

    # In a real application, the salt should be stored securely alongside the encrypted data.
    # For simplicity, we'll hardcode it here.  NEVER DO THIS IN PRODUCTION.
    salt = b'some_fixed_salt'  # Replace with a securely generated and stored salt.

    try:
        config_data = decrypt_config(encrypted_config, password, salt)
        # Parse the config data (e.g., using json or configparser)
        # For this example, we assume a simple string format: "username=xxx\npassword=yyy\nhostname=zzz"
        credentials = {}
        for line in config_data.splitlines():
            key, value = line.split("=", 1)
            credentials[key] = value
        return credentials['hostname'], credentials['username'], credentials['password']
    except Exception as e:
        print(f"Error decrypting or parsing configuration: {e}")
        return None, None, None


# --- FTP Download Function ---

def downloadFile(config_file, password, sensitive_file):
    """
    Connects to an FTP server, logs in, and downloads a file securely.

    Args:
        config_file: Path to the encrypted configuration file.
        password: Password to decrypt the configuration file.
        sensitive_file: The name of the file to download from the FTP server.
    """

    hostname, username, password_ftp = load_credentials(config_file, password)

    if not all([hostname, username, password_ftp]):
        print("Failed to load credentials. Aborting.")
        return

    try:
        ftp = ftplib.FTP(hostname)
        ftp.login(username, password_ftp)
        ftp.cwd(os.path.dirname(sensitive_file))  # Navigate to the directory

        # 1. Restricting file permissions:  Set restrictive permissions on the downloaded file.
        #    This is done *after* the file is downloaded.
        local_filename = os.path.basename(sensitive_file)
        with open(local_filename, 'wb') as f:
            ftp.retrbinary(f"RETR {os.path.basename(sensitive_file)}", f.write)

        # 1. Restricting file permissions (continued):  Set permissions to read/write for the owner only.
        try:
            os.chmod(local_filename, 0o600)  # Read/write for owner only
            print(f"File '{local_filename}' downloaded and permissions set to 0600.")
        except OSError as e:
            print(f"Warning: Could not set file permissions: {e}")

        ftp.quit()

    except ftplib.all_errors as e:
        print(f"FTP error: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")


# --- Example Usage ---

if __name__ == '__main__':
    # 1. & 6. & 7.  Example of creating and encrypting a configuration file:
    config_file = "ftp_config.enc"
    config_password = "my_secret_password"  # Replace with a strong password!
    salt = os.urandom(16)  # Generate a random salt. Store this securely!

    # Create a sample configuration (replace with your actual credentials)
    config_data = f"hostname=ftp.example.com\nusername=myusername\npassword=mypassword"

    # Encrypt and save the configuration
    encrypted_config = encrypt_config(config_data, config_password, salt)
    with open(config_file, 'wb') as f:
        f.write(encrypted_config)

    # Download a sensitive file
    sensitive_file_to_download = "path/to/sensitive_file.txt"  # Replace with the actual path on the FTP server
    downloadFile(config_file, config_password, sensitive_file_to_download)

