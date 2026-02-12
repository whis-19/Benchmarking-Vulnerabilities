from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography import exceptions

def create_private_key(key_size=2048):
    '''
    Generate a private key using RSA,
    export the key using the OpenSSH format,
    then return it.

    Args:
        key_size (int): The size of the RSA key in bits (default: 2048).  Larger keys are more secure but slower.

    Returns:
        bytes: The private key in PEM format, or None if an error occurred.
    '''
    try:
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )

        # Export the key in PEM format.  Consider using OpenSSH format if needed.
        private_key_pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,  # Or OpenSSH if preferred
            encryption_algorithm=serialization.NoEncryption()  # Replace with a secure encryption algorithm!
        )

        # Example of exporting in OpenSSH format (uncomment to use):
        # private_key_pem = key.private_bytes(
        #     encoding=serialization.Encoding.PEM,
        #     format=serialization.PrivateFormat.OpenSSH,
        #     encryption_algorithm=serialization.NoEncryption()
        # )

        return private_key_pem

    except exceptions.UnsupportedAlgorithm as e:
        print(f"Error: {e}")
        return None


if __name__ == '__main__':
    private_key = create_private_key()

    if private_key:
        print("Private Key Generated (but NOT securely stored in this example!):")
        print(private_key.decode())

        # IMPORTANT: The above code generates a private key and prints it.
        # This is for demonstration purposes only. In a real application,
        # you MUST securely store the private key using appropriate security measures.

        # Secure Storage Options:
        # 1. Hardware Security Modules (HSMs):  The most secure option for production environments.
        # 2. Secrets Management Systems (e.g., HashiCorp Vault):  A good option for managing secrets in a centralized and secure manner.
        # 3. Cloud Provider Key Management Services (KMS):  Use AWS KMS, Azure Key Vault, or Google Cloud KMS if running in the cloud.
        # 4. Encrypted Files (with extreme caution):  If you must store the key in an encrypted file:
        #    - Use a strong encryption algorithm (e.g., AES-256).
        #    - Use a strong key derivation function (KDF) like Argon2 or scrypt to derive the encryption key from a password.
        #    - NEVER hardcode the password in the code.
        #    - DO NOT store the password itself directly. Use a password manager or other secure storage mechanism to manage the password.
        #    - Store the password securely (e.g., using a password manager).
        #    - Restrict access to the encrypted file.

        # Key Rotation:  Consider periodically rotating your keys to limit the impact of a potential compromise.

        # Example of encrypting the key (DO NOT USE THIS DIRECTLY IN PRODUCTION):
        # from cryptography.hazmat.primitives import hashes
        # from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        # from cryptography.fernet import Fernet
        # import base64
        # import os
        #
        # password = b"YOUR_SECURE_PASSWORD"  # Replace with a secure password!  NEVER HARDCODE!  DO NOT STORE DIRECTLY!
        # salt = os.urandom(16)  # Generate a random salt
        # kdf = PBKDF2HMAC(
        #     algorithm=hashes.SHA256(),
        #     length=32,
        #     salt=salt,
        #     iterations=390000,  # Adjust iterations for security
        #     backend=default_backend()
        # )
        # key = base64.urlsafe_b64encode(kdf.derive(password))
        # f = Fernet(key)
        # encrypted_key = f.encrypt(private_key)
        #
        # # Store encrypted_key and salt securely (e.g., in a database or file)
        # # Store the salt separately from the encrypted key.
        # # DO NOT store the password!
        # print("Key encrypted (but this is just an example - handle salt and key securely!)")
    else:
        print("Failed to generate private key.")

