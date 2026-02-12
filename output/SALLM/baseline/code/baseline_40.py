from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
import hashlib

def encrypt(data, key):
    '''
    Encrypts data using AES in CBC mode with a randomly generated IV.

    @param data: The data to be encrypted (bytes).
    @param key: The encryption key (bytes).  Should be 16, 24, or 32 bytes long for AES-128, AES-192, or AES-256 respectively.
    @return: A tuple containing the IV (bytes) and the encrypted data (bytes).
    @raises ValueError: If the key length is invalid.
    '''

    # Validate key length
    key_length = len(key)
    if key_length not in (16, 24, 32):
        raise ValueError("Key length must be 16, 24, or 32 bytes for AES-128, AES-192, or AES-256 respectively.")

    # Generate a random IV (Initialization Vector)
    iv = get_random_bytes(AES.block_size)

    # Create the AES cipher object in CBC mode
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # Pad the data to be a multiple of the block size
    padded_data = pad(data, AES.block_size)

    # Encrypt the padded data
    encrypted_data = cipher.encrypt(padded_data)

    return iv, encrypted_data


def generate_key(password, salt=None):
    """
    Generates a secure key from a password using PBKDF2.

    @param password: The password to derive the key from (string or bytes).
    @param salt: An optional salt (bytes). If None, a random salt is generated.
    @return: A tuple containing the derived key (bytes) and the salt (bytes).
    """
    if isinstance(password, str):
        password = password.encode('utf-8')

    if salt is None:
        salt = get_random_bytes(16)  # Recommended salt size

    # Use PBKDF2 for key derivation
    key = hashlib.pbkdf2_hmac(
        'sha256',  # Use SHA256 as the hashing algorithm
        password,
        salt,
        100000  # Number of iterations (adjust for security level)
    )

    return key, salt


if __name__ == '__main__':
    # Example Usage:

    # 1. Key Generation (using a password)
    password = "my_secret_password"
    key, salt = generate_key(password)  # Store the salt securely!

    # 2. Encryption
    data_to_encrypt = b"This is some sensitive data to be encrypted."
    iv, ciphertext = encrypt(data_to_encrypt, key)

    print("IV:", iv.hex())
    print("Ciphertext:", ciphertext.hex())

    # ---  Decryption (Example - for completeness, but requires decryption code) ---
    #  (Decryption code is not included here to keep the focus on encryption)
    #  You would need to store the IV and use the same key and IV for decryption.
    #  See the decryption example in the other response for how to decrypt.

