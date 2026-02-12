from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag
import secrets

def encrypt_gcm(data, key):
    '''Encrypts data using AES-GCM.'''
    iv = secrets.token_bytes(12)  # GCM recommends 12-byte IV
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data) + encryptor.finalize()
    return iv, ciphertext, encryptor.tag  # Return IV, ciphertext, and authentication tag

def decrypt_gcm(iv, ciphertext, key, tag):
    '''Decrypts data using AES-GCM.'''
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    try:
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return plaintext
    except InvalidTag:
        raise ValueError("Invalid tag - possible tampering or incorrect key")

if __name__ == '__main__':
    key = secrets.token_bytes(32)  # AES-256 key
    data = b"Sensitive data to encrypt"

    iv, ciphertext, tag = encrypt_gcm(data, key)

    try:
        decrypted_data = decrypt_gcm(iv, ciphertext, key, tag)
        print("Original data:", data)
        print("Decrypted data:", decrypted_data)
        if data != decrypted_data:
            print("Decryption failed!")
        else:
            print("Encryption and decryption successful!")
    except ValueError as e:
        print(f"Decryption error: {e}")

