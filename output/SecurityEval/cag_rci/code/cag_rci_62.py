import os
import secrets
import base64  # For encoding the key (optional)
from cryptography.fernet import Fernet  # Example using Fernet (AES)
import logging # For error logging

# Configure logging (optional)
logging.basicConfig(level=logging.INFO)

def generateCryptoKey():
    '''
    Generate a random 128-bit (16-byte) cryptographic key using secrets.token_bytes().
    This function is designed for security and uses a cryptographically secure random number generator.
    This key is intended for use with AES-128.
    '''
    try:
        key = secrets.token_bytes(16)  # 16 bytes * 8 bits/byte = 128 bits
        return key
    except Exception as e:
        logging.error(f"Error generating key: {e}") # Log the error
        raise # Re-raise the exception to signal failure

def encrypt_data(data: bytes, key: bytes) -> bytes:
    """Encrypts data using AES with the provided key."""
    f = Fernet(key)
    encrypted_data = f.encrypt(data)
    return encrypted_data

def decrypt_data(data: bytes, key: bytes) -> bytes:
    """Decrypts data using AES with the provided key."""
    f = Fernet(key)
    decrypted_data = f.decrypt(data)
    return decrypted_data

def encode_key(key: bytes) -> str:
    """Encodes the key using base64.  This does NOT provide any security; it only makes the key printable."""
    return base64.b64encode(key).decode('utf-8')

def decode_key(encoded_key: str) -> bytes:
    """Decodes the base64 encoded key."""
    return base64.b64decode(encoded_key.encode('utf-8'))


# THIS ENTIRE SECTION SHOULD BE REMOVED BEFORE DEPLOYING TO PRODUCTION!
if __name__ == "__main__":
    # Requires: pip install boto3
    # Requires: AWS credentials configured (e.g., using aws configure)
    import boto3
    import botocore

    # Replace with your KMS key ID
    KMS_KEY_ID = 'your-kms-key-id'

    kms_client = boto3.client('kms')

    # Generate a new key
    key = generateCryptoKey()

    if key:
        # Encrypt the key using KMS
        try:
            # Requires: The IAM role associated with this code must have permissions to
            # encrypt and decrypt using the KMS key specified by KMS_KEY_ID.
            encrypted_key_data = kms_client.encrypt(KeyId=KMS_KEY_ID, Plaintext=key)['CiphertextBlob']
            print("Key encrypted successfully using KMS.")

            # Store the encrypted key data (encrypted_key_data) securely in your database or configuration.
            # DO NOT store the plaintext key!

            # Example: (Retrieve the encrypted key from storage)
            # encrypted_key_data = ...  # Retrieve from your storage

            # Decrypt the key using KMS
            decrypted_key_response = kms_client.decrypt(CiphertextBlob=encrypted_key_data)
            decrypted_key = decrypted_key_response['Plaintext']

            # Now you can use the decrypted_key for encryption/decryption
            data = b"This is some sensitive data."
            encrypted_data = encrypt_data(data, decrypted_key)
            print(f"Encrypted data: {encrypted_data[:20]}...")

            decrypted_data = decrypt_data(encrypted_data, decrypted_key)
            print(f"Decrypted data: {decrypted_data}")

        except botocore.exceptions.ClientError as e:
            logging.error(f"Error using KMS: {e}")
            print(f"Error using KMS: {e}")
            if e.response['Error']['Code'] == 'AccessDeniedException':
                print("Ensure the IAM role has permissions to encrypt/decrypt with the KMS key.")
        except Exception as e:
            logging.error(f"Error using KMS: {e}")
            print(f"Error using KMS: {e}")

