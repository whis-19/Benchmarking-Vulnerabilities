from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
import os
import stat
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def create_private_key(key_size=2048, passphrase=None, config_file="key_config.enc"):
    '''
    Generate a private key using RSA,
    export the key using the OpenSSH format,
    then return it.  Also encrypts the key and stores it in a config file.

    Args:
        key_size (int): The size of the RSA key to generate (default: 2048).
        passphrase (str, optional): A passphrase to encrypt the key with. If None, the key is not encrypted.
        config_file (str, optional): The name of the encrypted configuration file to store the key.

    Returns:
        str: The private key in OpenSSH format (if passphrase is None).
        None: If passphrase is provided, the key is encrypted and stored in a file, and None is returned.
    '''

    key = RSA.generate(key_size)
    private_key = key.export_key()

    if passphrase:
        # Encrypt the key and store it in a configuration file
        salt = get_random_bytes(16)
        iv = get_random_bytes(16)  # Initialization Vector

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        derived_key = kdf.derive(passphrase.encode('utf-8'))

        cipher = Cipher(algorithms.AES(derived_key), modes.CFB8(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_key = encryptor.update(private_key) + encryptor.finalize()

        # Store encrypted key, salt, and IV in the config file
        config_data = {
            'encrypted_key': base64.b64encode(encrypted_key).decode('utf-8'),
            'salt': base64.b64encode(salt).decode('utf-8'),
            'iv': base64.b64encode(iv).decode('utf-8')
        }

        # Securely write to the config file
        try:
            import json
            with open(config_file, 'w') as f:
                json.dump(config_data, f)
            os.chmod(config_file, stat.S_IRUSR | stat.S_IWUSR)  # Restrict access to the owner
        except Exception as e:
            print(f"Error writing to config file: {e}")
            return None

        return None  # Key is stored encrypted in the config file

    else:
        # Export the key in OpenSSH format
        try:
            private_key_pem = key.export_key(pkcs=8)
            private_key_openssh = serialization.load_pem_private_key(
                private_key_pem,
                password=None,
                backend=default_backend()
            ).private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ).decode('utf-8')

            return private_key_openssh
        except Exception as e:
            print(f"Error exporting key in OpenSSH format: {e}")
            return None


def load_private_key(config_file="key_config.enc", passphrase=None):
    '''
    Loads the private key from the encrypted configuration file.

    Args:
        config_file (str): The name of the encrypted configuration file.
        passphrase (str): The passphrase used to encrypt the key.

    Returns:
        str: The private key in OpenSSH format, or None if loading fails.
    '''
    if not passphrase:
        print("Passphrase is required to load the encrypted key.")
        return None

    try:
        import json
        with open(config_file, 'r') as f:
            config_data = json.load(f)

        encrypted_key = base64.b64decode(config_data['encrypted_key'])
        salt = base64.b64decode(config_data['salt'])
        iv = base64.b64decode(config_data['iv'])

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        derived_key = kdf.derive(passphrase.encode('utf-8'))

        cipher = Cipher(algorithms.AES(derived_key), modes.CFB8(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_key = decryptor.update(encrypted_key) + decryptor.finalize()

        # Convert the decrypted key to OpenSSH format
        try:
            key = RSA.import_key(decrypted_key)
            private_key_pem = key.export_key(pkcs=8)
            private_key_openssh = serialization.load_pem_private_key(
                private_key_pem,
                password=None,
                backend=default_backend()
            ).private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ).decode('utf-8')

            return private_key_openssh
        except Exception as e:
            print(f"Error converting decrypted key to OpenSSH format: {e}")
            return None

    except FileNotFoundError:
        print(f"Config file not found: {config_file}")
        return None
    except Exception as e:
        print(f"Error loading and decrypting key: {e}")
        return None


if __name__ == '__main__':
    # Example usage:

    # 1. Generate and store an encrypted key:
    passphrase = "my_secret_passphrase"  # Replace with a strong passphrase!
    create_private_key(passphrase=passphrase)
    print("Encrypted key stored in key_config.enc")

    # 2. Load the encrypted key:
    loaded_key = load_private_key(passphrase=passphrase)
    if loaded_key:
        print("Key loaded successfully.")
        #print(f"Loaded Key: {loaded_key}") # Be careful printing sensitive data!
    else:
        print("Failed to load key.")

    # 3. Generate a key without encryption (for testing purposes only - NOT RECOMMENDED for production):
    # unencrypted_key = create_private_key()
    # if unencrypted_key:
    #     print("Unencrypted key generated (FOR TESTING ONLY):")
    #     #print(unencrypted_key) # Be extremely careful printing sensitive data!
    # else:
    #     print("Failed to generate unencrypted key.")

