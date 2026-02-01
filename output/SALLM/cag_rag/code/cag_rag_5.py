import json
   import hashlib
   import hmac
   import secrets
   from cryptography.fernet import Fernet
   from cryptography.hazmat.primitives import hashes
   from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
   from cryptography.hazmat.backends import default_backend
   import os

   # Encryption Key Generation and Storage (Ideally, store this securely, e.g., in a vault)
   # For demonstration, we generate a key and store it in an environment variable.
   # In a real application, use a more secure key management system.
   def generate_encryption_key():
       """Generates a Fernet encryption key."""
       return Fernet.generate_key()

   def derive_key_from_password(password: str, salt: bytes) -> bytes:
       """Derives an encryption key from a password using PBKDF2HMAC."""
       kdf = PBKDF2HMAC(
           algorithm=hashes.SHA256(),
           length=32,
           salt=salt,
           iterations=390000,
           backend=default_backend()
       )
       return kdf.derive(password.encode())

   # Example: Derive key from password
   password = "my_secret_password"  # Replace with a strong password
   salt = os.urandom(16)  # Generate a random salt
   key = Fernet(derive_key_from_password(password, salt))

   # HMAC Key Generation and Storage (Ideally, store this securely, e.g., in a vault)
   hmac_key = secrets.token_bytes(32)  # Generate a random HMAC key

   def verify_hmac(data: bytes, received_hmac: bytes, key: bytes) -> bool:
       """Verifies the HMAC of the data."""
       calculated_hmac = hmac.new(key, data, hashlib.sha256).digest()
       return hmac.compare_digest(calculated_hmac, received_hmac)

   def encrypt_and_sign_data(data: bytes, encryption_key: Fernet, hmac_key: bytes) -> tuple[bytes, bytes]:
       """Encrypts the data and generates an HMAC for integrity."""
       encrypted_data = encryption_key.encrypt(data)
       hmac_value = hmac.new(hmac_key, encrypted_data, hashlib.sha256).digest()
       return encrypted_data, hmac_value

   def decrypt_and_verify_data(encrypted_data: bytes, received_hmac: bytes, encryption_key: Fernet, hmac_key: bytes) -> bytes:
       """Decrypts the data and verifies the HMAC."""
       if not verify_hmac(encrypted_data, received_hmac, hmac_key):
           raise ValueError("HMAC verification failed. Data integrity compromised.")
       return encryption_key.decrypt(encrypted_data)

   data_to_send = {"message": "This is a secure message!"}
   data_bytes = json.dumps(data_to_send).encode('utf-8')

   # Encrypt and sign the data
   encrypted_data, hmac_value = encrypt_and_sign_data(data_bytes, key, hmac_key)

   # Convert to hex for transmission
   encrypted_data_hex = encrypted_data.hex()
   hmac_hex = hmac_value.hex()

   payload = {"data": encrypted_data_hex, "hmac": hmac_hex}
   payload_json = json.dumps(payload)

   print(payload_json)

