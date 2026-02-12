from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import hmac
import hashlib
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256

def derive_keys(password, salt):
    '''Derives two 16-byte keys from a password and salt using PBKDF2-HMAC-SHA256: one for encryption, one for HMAC.'''
    key_enc = PBKDF2(password, salt, dklen=16, count=100000, prf=lambda x, y: hmac.new(x, y, SHA256).digest())
    key_hmac = PBKDF2(password, salt, dklen=16, count=100000, prf=lambda x, y: hmac.new(x, y, SHA256).digest())
    return key_enc, key_hmac


def encrypt(data, key_enc, key_hmac):
    '''
    Encrypts the data using AES in CBC mode with a randomly generated IV and HMAC for authentication.

    @param data: The data to be encrypted (bytes).
    @param key_enc: The encryption key (bytes).  Must be 16, 24, or 32 bytes long.
    @param key_hmac: The HMAC key (bytes).
    @return: A tuple containing the IV (bytes), the encrypted data (bytes), and the HMAC (bytes).
    @raises ValueError: If the key length is invalid.
    '''

    if len(key_enc) not in (16, 24, 32):
        raise ValueError("Encryption key must be 16, 24, or 32 bytes long")

    # Generate a random IV (Initialization Vector)
    iv = get_random_bytes(AES.block_size)

    # Create the AES cipher object in CBC mode
    cipher = AES.new(key_enc, AES.MODE_CBC, iv)

    # Pad the data to be a multiple of the block size (16 bytes for AES)
    padded_data = pad(data, AES.block_size)

    # Encrypt the padded data
    ciphertext = cipher.encrypt(padded_data)

    # Calculate HMAC for authentication (encrypt-then-MAC)
    hmac_obj = hmac.new(key_hmac, digestmod=hashlib.sha256)
    hmac_obj.update(iv)
    hmac_obj.update(ciphertext)
    hmac_value = hmac_obj.digest()

    return iv, ciphertext, hmac_value


def decrypt(iv, ciphertext, key_enc, key_hmac, hmac_value):
    '''
    Decrypts the ciphertext using AES in CBC mode and verifies the HMAC.

    @param iv: The Initialization Vector (bytes).
    @param ciphertext: The encrypted data (bytes).
    @param key_enc: The encryption key (bytes).
    @param key_hmac: The HMAC key (bytes).
    @param hmac_value: The HMAC (bytes) to verify.
    @return: The decrypted data (bytes).
    @raises ValueError: If the HMAC is invalid.
    '''
    # Verify HMAC
    hmac_obj = hmac.new(key_hmac, digestmod=hashlib.sha256)
    hmac_obj.update(iv)
    hmac_obj.update(ciphertext)
    expected_hmac = hmac_obj.digest()

    if not hmac.compare_digest(hmac_value, expected_hmac):
        raise ValueError("HMAC verification failed!  Possible tampering.")

    cipher = AES.new(key_enc, AES.MODE_CBC, iv)
    padded_data = cipher.decrypt(ciphertext)
    plaintext = unpad(padded_data, AES.block_size)
    return plaintext


if __name__ == '__main__':
    # Example Usage:
    password = b"MySuperSecretPassword"
    salt = get_random_bytes(16)  # Store this salt securely alongside the ciphertext!

    # The 'count' parameter in PBKDF2 (number of iterations) should be increased over time as hardware gets faster.
    key_enc, key_hmac = derive_keys(password, salt)

    data = b"This is some sensitive data to be encrypted."

    try:
        iv, ciphertext, hmac_value = encrypt(data, key_enc, key_hmac)

        # NEVER PRINT KEYS IN REAL CODE
        #print("Key:", key.hex())
        print("IV:", iv.hex())
        print("Ciphertext:", ciphertext.hex())
        print("HMAC:", hmac_value.hex())

        #  Important:  To decrypt, you'll need the key, IV, ciphertext, and HMAC.
        plaintext = decrypt(iv, ciphertext, key_enc, key_hmac, hmac_value)
        print("Plaintext:", plaintext.decode())

        # While CBC+HMAC is now more secure, consider using authenticated encryption modes like GCM or ChaCha20-Poly1305 for better security and efficiency.

    except ValueError as e:
        print(f"Error: {e}")

