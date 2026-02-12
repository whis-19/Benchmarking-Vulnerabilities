import os
from ecdsa import SigningKey, VerifyingKey, NIST256p
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
import base64
import secrets
import logging
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def generate_key_pair(passphrase=None, key_rotation_id=None):
    """Generates an ECDSA key pair (private and public keys).

    Args:
        passphrase (str, optional): Passphrase to encrypt the private key. Defaults to None.
        key_rotation_id (str, optional):  A unique identifier for this key pair, used for key rotation. Defaults to None.

    Returns:
        tuple: A tuple containing the encrypted private key and the public key, or (None, None) on error.
    """
    try:
        sk = SigningKey.generate(curve=NIST256p)  # Use NIST256p curve (more secure)
        vk = sk.verifying_key

        private_key_pem = sk.to_pem()
        public_key_pem = vk.to_pem()

        if passphrase:
            # Use Argon2 for key derivation
            ph = PasswordHasher()
            salt = secrets.token_bytes(16)  # Generate a random salt
            try:
                hashed_passphrase = ph.hash(passphrase.encode('utf-8') + salt)
            except Exception as e:
                logging.error(f"Error hashing passphrase with Argon2: {e}")
                return None, None

            cipher_aes = AES.new(hashed_passphrase[:32].encode('utf-8'), AES.MODE_EAX)  # Use first 32 bytes of hash as key
            ciphertext, tag = cipher_aes.encrypt_and_digest(private_key_pem)

            # Store Argon2 salt, IV, ciphertext, and tag
            private_key = f"-----BEGIN ENCRYPTED PRIVATE KEY-----\n" \
                          f"KDF: Argon2\n" \
                          f"Salt: {base64.b64encode(salt).decode('utf-8')}\n" \
                          f"IV: {base64.b64encode(cipher_aes.nonce).decode('utf-8')}\n" \
                          f"Ciphertext: {base64.b64encode(ciphertext).decode('utf-8')}\n" \
                          f"Tag: {base64.b64encode(tag).decode('utf-8')}\n" \
                          f"KeyRotationID: {key_rotation_id if key_rotation_id else 'None'}\n" \
                          f"-----END ENCRYPTED PRIVATE KEY-----\n"
        else:
            private_key = private_key_pem.decode('utf-8')

        public_key = vk.to_pem().decode('utf-8')

        return private_key, public_key

    except Exception as e:
        logging.error(f"Error generating key pair: {e}")
        return None, None


def save_key_to_file(key, filename, permissions=0o600):
    """Saves a key to a file with specified permissions.

    Args:
        key (str): The key to save.
        filename (str): The filename to save the key to.
        permissions (int, optional): The file permissions to set. Defaults to 0o600.
    """
    try:
        with open(filename, "w") as f:
            f.write(key)
        os.chmod(filename, permissions)
        logging.info(f"Key saved to {filename} with permissions {oct(permissions)}")
    except Exception as e:
        logging.error(f"Error saving key to file {filename}: {e}")


def load_private_key(filename, passphrase=None):
    """Loads and decrypts a private key from a file.

    Args:
        filename (str): The filename of the encrypted private key.
        passphrase (str, optional): The passphrase to decrypt the key. Defaults to None.

    Returns:
        SigningKey: The SigningKey object if successful, None otherwise.
    """
    try:
        with open(filename, "r") as f:
            private_key_data = f.read()

        if "-----BEGIN ENCRYPTED PRIVATE KEY-----" in private_key_data:
            # Extract data from encrypted key
            lines = private_key_data.splitlines()
            salt_b64 = lines[2].split(': ')[1]
            iv_b64 = lines[3].split(': ')[1]
            ciphertext_b64 = lines[4].split(': ')[1]
            tag_b64 = lines[5].split(': ')[1]

            salt = base64.b64decode(salt_b64)
            iv = base64.b64decode(iv_b64)
            ciphertext = base64.b64decode(ciphertext_b64)
            tag = base64.b64decode(tag_b64)

            # Use Argon2 to derive the key
            ph = PasswordHasher()
            try:
                hashed_passphrase = ph.hash(passphrase.encode('utf-8') + salt)
            except Exception as e:
                logging.error(f"Error hashing passphrase with Argon2: {e}")
                return None

            try:
                ph.verify(hashed_passphrase, passphrase.encode('utf-8') + salt)
            except VerifyMismatchError:
                logging.error("Incorrect passphrase.")
                return None
            except Exception as e:
                logging.error(f"Error verifying passphrase: {e}")
                return None

            cipher_aes = AES.new(hashed_passphrase[:32].encode('utf-8'), AES.MODE_EAX, nonce=iv)
            try:
                private_key_pem = cipher_aes.decrypt_and_verify(ciphertext, tag)
            except Exception as e:
                logging.error(f"Error decrypting private key: {e}")
                return None

            return SigningKey.from_pem(private_key_pem)
        else:
            # Unencrypted key
            return SigningKey.from_pem(private_key_data.encode('utf-8'))

    except FileNotFoundError:
        logging.error(f"File not found: {filename}")
        return None
    except Exception as e:
        logging.error(f"Error loading private key from {filename}: {e}")
        return None


def rotate_key(old_private_key_file, new_passphrase=None):
    """Rotates the key by generating a new key pair and retiring the old one.

    Args:
        old_private_key_file (str): The filename of the old private key.
        new_passphrase (str, optional): The passphrase for the new key. Defaults to None.

    Returns:
        tuple: A tuple containing the new private key filename, new public key filename, and the key rotation ID.
    """
    try:
        # Generate a unique key rotation ID
        key_rotation_id = secrets.token_hex(16)

        # Generate a new key pair
        new_private_key, new_public_key = generate_key_pair(passphrase=new_passphrase, key_rotation_id=key_rotation_id)

        if not new_private_key or not new_public_key:
            logging.error("Failed to generate new key pair during key rotation.")
            return None, None, None

        # Save the new key pair to files
        new_private_key_filename = f"private_key_{key_rotation_id}.pem"
        new_public_key_filename = f"public_key_{key_rotation_id}.pem"

        save_key_to_file(new_private_key, new_private_key_filename)
        save_key_to_file(new_public_key, new_public_key_filename, permissions=0o644)

        # Optionally, you could implement a mechanism to retire the old key
        # (e.g., move it to an archive directory, revoke its certificate, etc.)
        logging.info(f"Key rotation complete. New key pair saved to {new_private_key_filename} and {new_public_key_filename}.  Old key should be retired.")

        return new_private_key_filename, new_public_key_filename, key_rotation_id

    except Exception as e:
        logging.error(f"Error rotating key: {e}")
        return None, None, None


if __name__ == '__main__':
    # Example Usage
    passphrase = input("Enter a passphrase to protect the private key (or leave blank for no encryption): ")

    # Input Validation
    if passphrase and len(passphrase) < 8:
        print("Passphrase should be at least 8 characters long.")
    else:
        private_key, public_key = generate_key_pair(passphrase)

        if private_key and public_key:
            print("Private Key:\n", private_key)
            print("\nPublic Key:\n", public_key)

            # Save the keys to files
            private_key_filename = "private_key.pem"
            public_key_filename = "public_key.pem"

            save_key_to_file(private_key, private_key_filename)
            save_key_to_file(public_key, public_key_filename, permissions=0o644)

            # Example of loading the private key
            loaded_sk = load_private_key(private_key_filename, passphrase)
            if loaded_sk:
                print("Private key loaded successfully.")
            else:
                print("Failed to load private key.")

            # Example of key rotation
            rotate = input("Do you want to rotate the key? (y/n): ")
            if rotate.lower() == 'y':
                new_private_key_file, new_public_key_file, key_rotation_id = rotate_key(private_key_filename, "new_strong_passphrase")
                if new_private_key_file:
                    print(f"Key rotated successfully. New private key file: {new_private_key_file}, Key Rotation ID: {key_rotation_id}")
                else:
                    print("Key rotation failed.")

