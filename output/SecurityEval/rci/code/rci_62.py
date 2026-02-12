import secrets
import os
import base64  # Import needed for encoding derived key
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

def generateCryptoKey():
    '''
    Generate a random 128-bit (16-byte) cryptographic key using secrets.token_bytes().
    This function is designed for security and uses a cryptographically secure random number generator.
    '''
    try:
        key = secrets.token_bytes(16)  # 16 bytes * 8 bits/byte = 128 bits
        assert len(key) == 16, "Key length is not 16 bytes"  # Defensive check
        return key
    except Exception as e:
        print(f"Error generating key: {e}")
        return None  # Or raise the exception, depending on your needs

def encrypt_key(key, password):
    """Encrypts the key using a password-based key derivation function (PBKDF2) and Fernet."""
    password = password.encode()
    salt = os.urandom(16)  # Generate a unique salt for each encryption

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # Fernet key size
        salt=salt,
        iterations=390000,  # Increase for better security
        backend=default_backend()
    )
    derived_key = base64.urlsafe_b64encode(kdf.derive(password))
    f = Fernet(derived_key)
    encrypted_key = f.encrypt(key)
    return salt, encrypted_key

def decrypt_key(salt, encrypted_key, password):
    """Decrypts the key using the salt, encrypted key, and password."""
    password = password.encode()

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # Fernet key size
        salt=salt,
        iterations=390000,  # Must match encryption
        backend=default_backend()
    )
    derived_key = base64.urlsafe_b64encode(kdf.derive(password))
    f = Fernet(derived_key)
    key = f.decrypt(encrypted_key)
    return key


# Example usage (for demonstration purposes only - handle keys SECURELY!)
if __name__ == "__main__":
    key = generateCryptoKey()

    if key:
        # NEVER print the key in a production environment!
        # REMOVED PRINT STATEMENTS

        # WARNING: Base64 encoding is NOT encryption!  It only encodes binary data into text.
        # Do NOT use Base64 for storing cryptographic keys.  It is highly insecure.
        # encoded_key = base64.b64encode(key).decode('utf-8')
        # print(f"Encoded key (for example storage): {encoded_key}")

        # Instead, use a KMS, HSM, or encrypt the key before storing it.
        # Example: Encrypting the key with a password (NOT as secure as KMS/HSM!)
        password = "my_secret_password"  # Replace with a strong password!
        salt, encrypted_key = encrypt_key(key, password)

        # Store the salt and encrypted key securely (e.g., in a database or file)
        with open("key.enc", "wb") as f:
            f.write(salt)
            f.write(encrypted_key)

        print("Key encrypted and stored (but remember, this is a simplified example!)")

        # Example of retrieving the key (again, illustrative - secure retrieval is crucial)
        # Retrieve the salt and encrypted key from storage
        with open("key.enc", "rb") as f:
            salt = f.read(16)  # Salt is 16 bytes
            encrypted_key = f.read()

        # Decrypt the key
        try:
            retrieved_key = decrypt_key(salt, encrypted_key, password)
            print("Key successfully decrypted.")
            # Now you can use the retrieved_key for encryption/decryption
            # (but make sure the encryption/decryption process is also secure!)
        except Exception as e:
            print(f"Error decrypting key: {e}")

        # Key Rotation:  Cryptographic keys should be rotated periodically.
        # See: [Link to key rotation best practices]

        # Secure Encryption/Decryption:  Use authenticated encryption modes like AES-GCM.
        # See: [Link to secure encryption practices]

