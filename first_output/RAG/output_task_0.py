import os
import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
import base64

class SecureIDStorage:
    def __init__(self, storage_path):
        self.storage_path = storage_path
        self.salt_file = os.path.join(self.storage_path, "salt")
        self.key_file = os.path.join(self.storage_path, "key")
        self.id_file = os.path.join(self.storage_path, "id_data")
        self.ensure_storage_exists()

    def ensure_storage_exists(self):
        if not os.path.exists(self.storage_path):
            os.makedirs(self.storage_path)

    def generate_salt(self):
        return os.urandom(16)

    def generate_key(self, password, salt):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key

    def securely_store_id(self, hardware_id, password):
        salt = self.generate_salt()
        with open(self.salt_file, "wb") as f:
            f.write(salt)

        key = self.generate_key(password, salt)
        with open(self.key_file, "wb") as f:
            f.write(key)  #Ideally, store this key in Android Keystore

        f = Fernet(key)
        encrypted_id = f.encrypt(hardware_id.encode())

        with open(self.id_file, "wb") as f:
            f.write(encrypted_id)

    def retrieve_id(self, password):
        try:
            with open(self.salt_file, "rb") as f:
                salt = f.read()
            with open(self.key_file, "rb") as f:
                key = f.read() # Ideally, retrieve key from Android Keystore
            with open(self.id_file, "rb") as f:
                encrypted_id = f.read()
        except FileNotFoundError:
            return None

        # Ensure password matches the key used for encryption
        try:
            f = Fernet(key)
            decrypted_id = f.decrypt(encrypted_id).decode()
            return decrypted_id
        except:  #Handle cases where key is invalid due to incorrect password or corrupted key file.
            return None

    def delete_id(self):
        try:
            os.remove(self.salt_file)
            os.remove(self.key_file)
            os.remove(self.id_file)
        except FileNotFoundError:
            pass #Files don't exist, nothing to delete