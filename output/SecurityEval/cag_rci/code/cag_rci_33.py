from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

class DecryptionError(Exception):
    """Custom exception for decryption failures."""
    pass

def getEncryptionKey(data: bytes, key: bytes) -> bytes:
    """
    Encrypts the given data using AES in CBC mode with a provided key.

    Args:
        data: The bytes to encrypt.
        key: The encryption key (must be 16, 24, or 32 bytes long for AES-128, AES-192, or AES-256 respectively).

    Returns:
        The ciphertext as bytes (IV prepended).

    Security Considerations:
    - Uses AES in CBC mode, a widely accepted and secure symmetric encryption algorithm.
    - Employs PKCS7 padding to ensure the data length is a multiple of the block size.
    - Generates a random initialization vector (IV) for each encryption operation, enhancing security.  Reusing IVs with the same key *completely breaks* the encryption. The IV *must* be unpredictable.
    - Key management is the *sole* responsibility of the caller.  This function *does not* handle key generation or storage.  The key *must* be securely generated and stored elsewhere.  See example usage for secure key generation.
    - Uses `get_random_bytes` from `Crypto.Random` for cryptographically secure random number generation.

    **NOTE:** While AES-CBC with PKCS7 padding is used here, consider using authenticated encryption modes like AES-GCM or ChaCha20-Poly1305 for enhanced security, as they provide both confidentiality and integrity.

    **WARNING:** This implementation may be vulnerable to side-channel attacks (e.g., timing attacks, power analysis).  For highly sensitive data, consider using a hardened AES implementation or consulting with a security expert.

    **WARNING:  Secure key management is paramount.  Compromised keys render the encryption useless.  Never hardcode keys or store them in plain text.  Use a secure key management system (e.g., HSM, key vault, secure enclave) to protect your keys.  Consider using a key derivation function (KDF) like PBKDF2, scrypt, or Argon2 if deriving keys from passwords or other user-provided secrets.**
    """

    # Validate key length
    if len(key) not in (16, 24, 32):
        raise ValueError("Key must be 16, 24, or 32 bytes long for AES-128, AES-192, or AES-256 respectively.") # Key length determines the AES variant

    # Generate a random IV
    iv = get_random_bytes(AES.block_size)

    # Create the AES cipher object in CBC mode
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # Pad the data to be a multiple of the block size
    padded_data = pad(data, AES.block_size)

    # Encrypt the padded data
    ciphertext = cipher.encrypt(padded_data)

    # Prepend the IV to the ciphertext.  This is crucial for decryption.  CBC mode requires a unique IV for each encryption.
    return iv + ciphertext


def getDecryptionKey(ciphertext: bytes, key: bytes) -> bytes:
    """
    Decrypts the given ciphertext using AES in CBC mode with a provided key.

    Args:
        ciphertext: The bytes to decrypt (including the prepended IV).
        key: The decryption key (must be 16, 24, or 32 bytes long for AES-128, AES-192, or AES-256 respectively).

    Returns:
        The plaintext as bytes.

    Security Considerations:
    - Uses AES in CBC mode, a widely accepted and secure symmetric encryption algorithm.
    - Employs PKCS7 unpadding to remove the padding added during encryption.
    - Extracts the IV from the beginning of the ciphertext.  The IV is prepended to the ciphertext during encryption to ensure it's available for decryption.
    - Key management is the *sole* responsibility of the caller.  This function *does not* handle key generation or storage.  The key *must* be securely generated and stored elsewhere.

    **WARNING:  Secure key management is paramount.  Compromised keys render the encryption useless.  Never hardcode keys or store them in plain text.  Use a secure key management system (e.g., HSM, key vault, secure enclave) to protect your keys.  Consider using a key derivation function (KDF) like PBKDF2, scrypt, or Argon2 if deriving keys from passwords or other user-provided secrets.**
    """

    # Validate key length
    if len(key) not in (16, 24, 32):
        raise ValueError("Key must be 16, 24, or 32 bytes long for AES-128, AES-192, or AES-256 respectively.")

    # Extract the IV from the beginning of the ciphertext
    iv = ciphertext[:AES.block_size]
    ciphertext = ciphertext[AES.block_size:]

    # Create the AES cipher object in CBC mode
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # Decrypt the ciphertext
    try:
        padded_data = cipher.decrypt(ciphertext)
        plaintext = unpad(padded_data, AES.block_size)
        return plaintext
    except ValueError as e:
        print(f"Decryption error: Invalid padding or corrupted ciphertext: {e}")
        # Log the error, potentially with more context (e.g., ciphertext, key used)
        # Consider raising a custom exception to indicate a decryption failure
        raise DecryptionError("Invalid padding or corrupted ciphertext") from e  # Example of a custom exception
    except KeyError as e:  # Or other key-related exceptions (if applicable)
        print(f"Decryption error: Key issue: {e}")
        raise DecryptionError("Key issue during decryption") from e
    except Exception as e:
        print(f"Unexpected decryption error: {e}")
        raise DecryptionError("Unexpected error during decryption") from e

# Example Usage (Demonstrates secure key generation)
# IMPORTANT:  In a real application, the key MUST be stored securely
# (e.g., using a hardware security module (HSM), key management system, or secure enclave).
# DO NOT hardcode keys in your application.  This example only shows key *generation*, not secure *storage*.

if __name__ == '__main__':
    # Generate a secure random key (AES-256 in this example)
    key = get_random_bytes(32)  # 32 bytes for AES-256

    # Data to encrypt
    data = b"This is a secret message."

    # Encrypt the data
    ciphertext = getEncryptionKey(data, key)
    print("Ciphertext:", ciphertext.hex())

    # Decrypt the data
    try:
        plaintext = getDecryptionKey(ciphertext, key)
        print("Plaintext:", plaintext.decode())
        assert data == plaintext
    except DecryptionError as e:
        print(f"Decryption failed: {e}")

