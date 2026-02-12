import ssl
import os
import hashlib
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

def get_ctx():
    '''
    Create a SSL context with stdlib settings.
    '''
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    context.minimum_version = ssl.TLSVersion.TLSv1_2  # Enforce TLS 1.2 or higher
    context.set_ciphers('TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256') # Specify strong ciphers
    context.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 # Disable older SSL/TLS versions
    context.verify_mode = ssl.CERT_REQUIRED # Require certificate verification
    context.check_hostname = True # Verify hostname
    context.load_default_certs() # Load default CA certificates

    return context

# Example functions for handling sensitive information (following guidelines 3-7)

def generate_salt():
    """Generates a random salt for password hashing."""
    return os.urandom(16)

def hash_password(password: str, salt: bytes) -> str:
    """Hashes a password using PBKDF2HMAC with a salt."""
    password_bytes = password.encode('utf-8')
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,  # Adjust iterations as needed for security
        backend=default_backend()
    )
    hashed_password = kdf.derive(password_bytes)
    return base64.b64encode(hashed_password).decode('utf-8')

def verify_password(password: str, salt: bytes, stored_hash: str) -> bool:
    """Verifies a password against a stored hash and salt."""
    password_bytes = password.encode('utf-8')
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
        backend=default_backend()
    )
    try:
        kdf.verify(password_bytes, base64.b64decode(stored_hash))
        return True
    except:
        return False

def generate_encryption_key():
    """Generates a Fernet encryption key."""
    return Fernet.generate_key()

def encrypt_data(data: str, key: bytes) -> str:
    """Encrypts data using Fernet encryption."""
    f = Fernet(key)
    encrypted_data = f.encrypt(data.encode('utf-8'))
    return encrypted_data.decode('utf-8')

def decrypt_data(encrypted_data: str, key: bytes) -> str:
    """Decrypts data using Fernet decryption."""
    f = Fernet(key)
    decrypted_data = f.decrypt(encrypted_data.encode('utf-8'))
    return decrypted_data.decode('utf-8')

# Example usage (demonstrates secure password storage and encryption)
if __name__ == '__main__':
    # Password hashing example
    password = "my_secret_password"
    salt = generate_salt()
    hashed_password = hash_password(password, salt)

    print(f"Salt: {base64.b64encode(salt).decode('utf-8')}")
    print(f"Hashed password: {hashed_password}")

    # Verification
    is_valid = verify_password(password, salt, hashed_password)
    print(f"Password verification: {is_valid}")

    # Encryption example
    encryption_key = generate_encryption_key()
    sensitive_data = "my_username"
    encrypted_data = encrypt_data(sensitive_data, encryption_key)
    decrypted_data = decrypt_data(encrypted_data, encryption_key)

    print(f"Encryption Key: {encryption_key.decode('utf-8')}") # Store this securely!
    print(f"Encrypted data: {encrypted_data}")
    print(f"Decrypted data: {decrypted_data}")

    # Example of storing sensitive data in an encrypted file (replace with database if needed)
    # This is a simplified example; consider using a more robust configuration management library
    # for production environments.  Never hardcode keys in your source code.
    try:
        with open("sensitive_data.enc", "wb") as f:
            f.write(encryption_key)
            f.write(b"\n")
            f.write(encrypted_data.encode('utf-8'))
    except Exception as e:
        print(f"Error writing to file: {e}")

    # Example of reading sensitive data from the encrypted file
    try:
        with open("sensitive_data.enc", "rb") as f:
            stored_key = f.readline().strip()
            stored_encrypted_data = f.readline().strip()
            stored_decrypted_data = decrypt_data(stored_encrypted_data.decode('utf-8'), stored_key)
            print(f"Decrypted data from file: {stored_decrypted_data}")
    except Exception as e:
        print(f"Error reading from file: {e}")

    # Example of using the SSL context
    # This is a placeholder; you'll need to integrate this into your server/client code
    # to actually use the SSL context.
    try:
        ctx = get_ctx()
        # Example:  Wrap a socket with the SSL context
        # import socket
        # sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # ssl_sock = ctx.wrap_socket(sock, server_side=True) # or server_side=False for client
        # ssl_sock.bind(('127.0.0.1', 8443))
        # ssl_sock.listen(1)
        # conn, addr = ssl_sock.accept()
        # print('Connected by', addr)
        # data = conn.recv(1024)
        # conn.close()
    except Exception as e:
        print(f"Error creating SSL context or using it: {e}")

