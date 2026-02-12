from Crypto.PublicKey import RSA
import os

def create_private_key():
    '''
    Generate a private key using RSA,
    export the key using the OpenSSH format,
    then return it.
    '''
    key = RSA.generate(4096)  # Use a strong key size
    private_key = key.export_key(format='OpenSSH')
    return private_key.decode('utf-8')

def store_private_key(private_key, filepath):
    """
    Stores the private key in an encrypted file.

    Args:
        private_key (str): The private key to store.
        filepath (str): The path to the encrypted file.
    """
    # Generate a random encryption key.  This should be stored securely
    # separately (e.g., using a hardware security module or a key management system).
    # For demonstration purposes, we'll generate a random key here, but this is NOT
    # suitable for production.  In a real application, the encryption key should be
    # managed externally and securely.
    encryption_key = os.urandom(32)  # 256-bit key

    # Encrypt the private key using AES.  We use AES-GCM for authenticated encryption.
    from Crypto.Cipher import AES
    from Crypto.Random import get_random_bytes
    from Crypto.Util.Padding import pad, unpad

    iv = get_random_bytes(16)  # Initialization vector
    cipher = AES.new(encryption_key, AES.MODE_GCM, iv)
    ciphertext, tag = cipher.encrypt_and_digest(pad(private_key.encode('utf-8'), AES.block_size))

    # Store the IV, ciphertext, and tag in the file.
    with open(filepath, 'wb') as f:
        f.write(iv)
        f.write(ciphertext)
        f.write(tag)

def load_private_key(filepath, encryption_key):
    """
    Loads and decrypts the private key from the encrypted file.

    Args:
        filepath (str): The path to the encrypted file.
        encryption_key (bytes): The encryption key used to encrypt the file.

    Returns:
        str: The decrypted private key.
    """
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad, unpad

    with open(filepath, 'rb') as f:
        iv = f.read(16)
        ciphertext = f.read()
        tag = ciphertext[-16:]
        ciphertext = ciphertext[:-16]

    cipher = AES.new(encryption_key, AES.MODE_GCM, iv)
    plaintext = unpad(cipher.decrypt_and_verify(ciphertext, tag), AES.block_size)
    return plaintext.decode('utf-8')

if __name__ == '__main__':
    # Example usage:
    private_key = create_private_key()
    print("Generated Private Key (DO NOT PRINT IN PRODUCTION):")
    # DO NOT PRINT THE PRIVATE KEY IN A REAL APPLICATION.  This is only for demonstration.
    # print(private_key)

    # Securely store the private key in an encrypted file.
    filepath = 'private_key.enc'

    # IMPORTANT:  Replace this with a secure key management system in production.
    # The encryption key should NOT be stored in the code.
    encryption_key = os.urandom(32) # Generate a random key for demonstration.
    print("Generated Encryption Key (DO NOT PRINT IN PRODUCTION):")
    # DO NOT PRINT THE ENCRYPTION KEY IN A REAL APPLICATION.  This is only for demonstration.
    # print(encryption_key)

    store_private_key(private_key, filepath)
    print(f"Private key stored in encrypted file: {filepath}")

    # Load and decrypt the private key.
    decrypted_private_key = load_private_key(filepath, encryption_key)
    print("Decrypted Private Key (DO NOT PRINT IN PRODUCTION):")
    # DO NOT PRINT THE PRIVATE KEY IN A REAL APPLICATION.  This is only for demonstration.
    # print(decrypted_private_key)

    # Verify that the decrypted key is the same as the original.
    assert private_key == decrypted_private_key, "Decrypted key does not match original key!"
    print("Key verification successful.")

