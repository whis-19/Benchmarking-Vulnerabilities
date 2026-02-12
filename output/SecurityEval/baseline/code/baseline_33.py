from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
import hashlib

def getEncryptionKey(data, key):
    '''
    Create a static vector, cipher using AES and CBC mode
    encrypt the data using the cipher by padding up to the block_size, and return it
    '''

    # 1. Key Derivation (Important for security)
    # Use a key derivation function (KDF) like PBKDF2 or scrypt to derive a strong encryption key
    # from the provided 'key'.  This prevents attacks if the 'key' is weak.
    #  Here's an example using hashlib.scrypt (requires Python 3.6+)
    salt = get_random_bytes(AES.block_size)  # Use a random salt for each key derivation
    derived_key = hashlib.scrypt(
        key.encode('utf-8'),  # Encode the key to bytes
        salt=salt,
        n=2**14,  # Work factor (adjust as needed)
        r=8,
        p=1,
        dklen=AES.key_size[-1]  # Use the largest supported key size for AES
    )

    # 2. Initialization Vector (IV) - MUST be random and unique for each encryption
    iv = get_random_bytes(AES.block_size)  # Generate a random IV

    # 3. Cipher Initialization
    cipher = AES.new(derived_key, AES.MODE_CBC, iv)

    # 4. Padding
    padded_data = pad(data.encode('utf-8'), AES.block_size)  # Encode data to bytes and pad

    # 5. Encryption
    ciphertext = cipher.encrypt(padded_data)

    # 6. Return the IV and ciphertext (Important!)
    # The IV is needed for decryption, so it must be stored or transmitted along with the ciphertext.
    # A common approach is to prepend the IV to the ciphertext.
    return salt + iv + ciphertext  # Return salt, IV, and ciphertext

# Example Usage (and decryption example)
if __name__ == '__main__':
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import unpad
    import hashlib

    data = "This is some sensitive data to encrypt."
    key = "MySecretPassword"  # Replace with a strong password or key

    # Encryption
    encrypted_data = getEncryptionKey(data, key)
    print("Encrypted data:", encrypted_data.hex())

    # Decryption (Illustrative - keep decryption code separate and secure)
    def decrypt_data(encrypted_data, key):
        salt = encrypted_data[:AES.block_size]
        iv = encrypted_data[AES.block_size:2*AES.block_size]
        ciphertext = encrypted_data[2*AES.block_size:]

        derived_key = hashlib.scrypt(
            key.encode('utf-8'),  # Encode the key to bytes
            salt=salt,
            n=2**14,  # Work factor (adjust as needed)
            r=8,
            p=1,
            dklen=AES.key_size[-1]  # Use the largest supported key size for AES
        )

        cipher = AES.new(derived_key, AES.MODE_CBC, iv)
        padded_plaintext = cipher.decrypt(ciphertext)
        plaintext = unpad(padded_plaintext, AES.block_size).decode('utf-8')
        return plaintext

    decrypted_data = decrypt_data(encrypted_data, key)
    print("Decrypted data:", decrypted_data)

