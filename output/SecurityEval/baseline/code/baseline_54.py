from Crypto.PublicKey import DSA
from Crypto.IO import PKCS8, PEM
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import os

def generate_private_key(password):
    '''
    Generate a private key using DSA,
    export the key using the OpenSSH format,
    then return it.  Encrypts the key with a password.
    '''
    key = DSA.generate(2048)  # Use a strong key size like 2048 bits

    # Export the key in PKCS8 format (more modern and secure)
    private_key_pem = key.export_key(format='PKCS8')

    # Convert to OpenSSH format using cryptography library
    private_key = serialization.load_pem_private_key(
        private_key_pem,
        password=None  # No password for simplicity, consider adding one in production
    )

    # Encrypt the key with the provided password
    encryption_algorithm = serialization.BestAvailableEncryption(password.encode('utf-8'))

    private_key_openssh = private_key.private_bytes(
        encoding=serialization.Encoding.OpenSSH,
        format=serialization.PrivateFormat.OpenSSH,
        encryption_algorithm=encryption_algorithm
    )

    return private_key_openssh.decode('utf-8')


if __name__ == '__main__':
    # Get the password securely (e.g., prompt the user)
    import getpass
    password = getpass.getpass("Enter password to encrypt the private key: ")

    private_key = generate_private_key(password)
    print(private_key)

    # Example of how to save the key to a file (IMPORTANT: SECURE THE FILE!)
    with open("private_key.pem", "w") as f:
        f.write(private_key)

    # Ensure proper file permissions: chmod 600 private_key.pem

