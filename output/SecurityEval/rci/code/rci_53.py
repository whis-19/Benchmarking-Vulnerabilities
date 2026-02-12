from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import PKCS1_OAEP  # For encrypting with a public key
from getpass import getpass  # For secure password input
import os
import stat  # For file permission constants
import secrets  # For generating strong random numbers
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def create_private_key(passphrase=None, key_size=4096):
    '''
    Generate a private key using RSA,
    export the key using the OpenSSH format,
    then return it.  Optionally encrypts the key with a passphrase.
    Returns both private and public keys.
    '''
    try:
        # Use secrets.randbits for more robust entropy
        key = RSA.generate(key_size, lambda n: secrets.randbits(n * 8).to_bytes(n, 'big'))

        if passphrase:
            # Encrypt the private key with a passphrase using PKCS#8
            private_key_pem = key.export_key(format='OpenSSH', passphrase=passphrase, pkcs=8)
        else:
            private_key_pem = key.export_key(format='OpenSSH')

        public_key = key.publickey().export_key(format='OpenSSH')

        return private_key_pem.decode('utf-8'), public_key.decode('utf-8')

    except Exception as e:
        logging.error(f"Error generating private key: {e}", exc_info=True)  # Log full exception info
        return None, None


def save_key_to_file(key, filepath, permissions=0o600):
    """
    Saves a key (private or public) to a file, setting specified permissions.

    Args:
        key (str): The key to save.
        filepath (str): The path to the file.
        permissions (int):  File permissions (e.g., 0o600 for owner-only read/write).
    """
    try:
        # Ensure the directory exists
        os.makedirs(os.path.dirname(filepath), exist_ok=True)

        with open(filepath, "w") as f:
            f.write(key)
        os.chmod(filepath, permissions)  # Restrict access to the owner
        logging.info(f"Key stored securely in {filepath} with permissions {oct(permissions)}")
        return True
    except Exception as e:
        logging.error(f"Error storing key to {filepath}: {e}", exc_info=True)
        return False


def is_strong_passphrase(passphrase, min_length=12):
    """
    Checks if a passphrase meets minimum length and complexity requirements.
    """
    if len(passphrase) < min_length:
        return False, f"Passphrase must be at least {min_length} characters long."

    # Add more complexity checks here if needed (e.g., require uppercase, lowercase, digits, symbols)
    # For example:
    # if not any(c.isupper() for c in passphrase):
    #     return False, "Passphrase must contain at least one uppercase character."

    return True, None


if __name__ == '__main__':
    # Secure key storage location
    KEY_DIR = os.path.expanduser("~/.ssh")  # Store in ~/.ssh directory
    PRIVATE_KEY_PATH = os.path.join(KEY_DIR, "id_rsa")
    PUBLIC_KEY_PATH = os.path.join(KEY_DIR, "id_rsa.pub")

    # Ensure the .ssh directory exists and has correct permissions
    if not os.path.exists(KEY_DIR):
        try:
            os.makedirs(KEY_DIR, mode=0o700)  # Owner-only access
            logging.info(f"Created directory {KEY_DIR} with permissions 0o700")
        except OSError as e:
            logging.error(f"Failed to create directory {KEY_DIR}: {e}", exc_info=True)
            exit(1)
    else:
        # Verify directory permissions
        mode = os.stat(KEY_DIR).st_mode
        if stat.S_IMODE(mode) != 0o700:
            logging.warning(f"Directory {KEY_DIR} has incorrect permissions.  Expected 0o700, got {oct(stat.S_IMODE(mode))}.  Please correct manually.")


    while True:
        use_passphrase = input("Do you want to encrypt the private key with a passphrase? (y/n): ").lower() == 'y'
        if use_passphrase:
            passphrase = getpass("Enter a passphrase to protect the private key: ")
            strength, message = is_strong_passphrase(passphrase)
            if strength:
                break  # Exit loop if passphrase is strong enough
            else:
                print(message)
        else:
            passphrase = None
            break  # Exit loop if no passphrase is desired

    private_key, public_key = create_private_key(passphrase)

    if private_key and public_key:
        # Securely store the private key in a file
        private_key_saved = save_key_to_file(private_key, PRIVATE_KEY_PATH)
        public_key_saved = save_key_to_file(public_key, PUBLIC_KEY_PATH, permissions=0o644) # Public key can be world-readable

        if not private_key_saved:
            print("Failed to save private key.")
        if not public_key_saved:
            print("Failed to save public key.")


    else:
        print("Failed to generate private key.")

