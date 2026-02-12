# Example using AES-GCM (requires a key and nonce)
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def encrypt_gcm(plaintext, key, nonce):
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext.encode('utf-8')) + encryptor.finalize()
    return ciphertext, encryptor.tag  # GCM returns a tag for authentication

def decrypt_gcm(ciphertext, key, nonce, tag):
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext.decode('utf-8')

# Example Usage (replace with securely generated key and nonce)
# key = secrets.token_bytes(32)  # 256-bit key
# nonce = secrets.token_bytes(12)  # GCM recommends 12-byte nonce
# ciphertext, tag = encrypt_gcm("My secret message", key, nonce)
# decrypted_plaintext = decrypt_gcm(ciphertext, key, nonce, tag)
# print(f"Decrypted (GCM): {decrypted_plaintext}")

