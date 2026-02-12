from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
import os

def encrypt(data, key):
    '''
    Encrypts the data using AES in CBC mode with a randomly generated IV.
    The IV is prepended to the ciphertext.

    @param data: The data to be encrypted (bytes).
    @param key: The encryption key (bytes).  Must be 16, 24, or 32 bytes long.
    @return: The encrypted data (bytes).
    '''

    # Generate a random IV (Initialization Vector)
    iv = get_random_bytes(AES.block_size)

    # Create the cipher object
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # Pad the data to be a multiple of the block size
    padded_data = pad(data, AES.block_size)

    # Encrypt the data
    ciphertext = cipher.encrypt(padded_data)

    # Prepend the IV to the ciphertext
    # This is crucial for decryption.  The IV must be available.
    # Prepending is a common and secure way to handle this.
    return iv + ciphertext


def decrypt(ciphertext, key):
    '''
    Decrypts the data encrypted with the `encrypt` function.

    @param ciphertext: The ciphertext (bytes), including the prepended IV.
    @param key: The encryption key (bytes).  Must be the same key used for encryption.
    @return: The decrypted data (bytes).
    '''
    # Extract the IV from the beginning of the ciphertext
    iv = ciphertext[:AES.block_size]
    ciphertext = ciphertext[AES.block_size:]

    # Create the cipher object
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # Decrypt the data
    padded_data = cipher.decrypt(ciphertext)

    # Unpad the data
    from Crypto.Util.Padding import unpad
    data = unpad(padded_data, AES.block_size)

    return data


# Example Usage (and demonstration of key handling best practices)
if __name__ == '__main__':
    # 1. Key Generation and Storage (Illustrative - DO NOT HARDCODE KEYS!)
    # In a real application, the key should be:
    #   - Generated securely (e.g., using os.urandom or a hardware security module)
    #   - Stored securely (e.g., in a dedicated key management system, hardware security module, or encrypted configuration file with restricted access).
    #   - Never hardcoded in the source code.

    # For demonstration purposes, we'll generate a random key here.  NEVER DO THIS IN PRODUCTION.
    key = os.urandom(32)  # 256-bit key (AES-256)

    # 2. Data to Encrypt
    data = b"This is some sensitive data that needs to be encrypted."

    # 3. Encryption
    ciphertext = encrypt(data, key)
    print("Ciphertext:", ciphertext.hex())

    # 4. Decryption
    decrypted_data = decrypt(ciphertext, key)
    print("Decrypted data:", decrypted_data.decode())

    # 5. Key Rotation (Illustrative)
    # In a real application, keys should be rotated regularly.  This involves:
    #   - Generating a new key.
    #   - Re-encrypting data with the new key.
    #   - Securely destroying the old key (after ensuring all data is re-encrypted).
    # This example just shows generating a new key; the re-encryption and destruction steps are crucial in a real system.
    # new_key = os.urandom(32) # Generate a new key
    # ... (re-encrypt data with new_key)
    # ... (securely destroy old key)

    # Demonstrating incorrect key length
    try:
        invalid_key = os.urandom(15) # Invalid key length
        encrypt(data, invalid_key)
    except ValueError as e:
        print(f"Error: {e}")

