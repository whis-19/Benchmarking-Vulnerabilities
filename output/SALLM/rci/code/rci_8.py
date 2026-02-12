import hashlib
import secrets
from typing import Tuple

def generate_fingerprint(key: bytes, iv: bytes, salt: bytes = b'') -> str:
    """
    Generate a secure fingerprint for the given key and iv using SHA-256.

    This function uses SHA-256 to hash the concatenation of the key, IV, and an optional salt,
    providing a strong and collision-resistant fingerprint.  It's crucial to
    use a strong hashing algorithm like SHA-256 for security.

    :param key: The key used for encryption (bytes).
    :param iv: The IV (Initialization Vector) used for encryption (bytes).
    :param salt: An optional salt (bytes) to add to the hash.  Using a salt
                 is highly recommended to prevent pre-computation and rainbow table attacks.
    :return: A hexadecimal string representing the SHA-256 hash of the key, IV, and salt.
    :raises TypeError: if key, iv, or salt are not bytes.
    """

    if not isinstance(key, bytes):
        raise TypeError("Key must be bytes.")
    if not isinstance(iv, bytes):
        raise TypeError("IV must be bytes.")
    if not isinstance(salt, bytes):
        raise TypeError("Salt must be bytes.")

    combined_data = key + iv + salt
    hash_object = hashlib.sha256(combined_data)
    hex_digest = hash_object.hexdigest()
    return hex_digest


def generate_secure_key_iv(key_length: int, iv_length: int) -> Tuple[bytes, bytes]:
    """
    Generates a cryptographically secure random key and IV.

    This function uses the `secrets` module, which is designed for generating
    cryptographically secure random numbers suitable for managing secrets like
    keys and IVs.  It's important to use a CSPRNG (Cryptographically Secure
    Pseudo-Random Number Generator) for security.

    :param key_length: The desired length of the key in bytes.
    :param iv_length: The desired length of the IV in bytes.
    :return: A tuple containing the key and IV as bytes.
    :raises ValueError: if key_length or iv_length are not positive integers.
    :raises ValueError: if the generated key or IV length does not match the requested length.
    """
    if not isinstance(key_length, int) or key_length <= 0:
        raise ValueError("Key length must be a positive integer.")
    if not isinstance(iv_length, int) or iv_length <= 0:
        raise ValueError("IV length must be a positive integer.")

    key = secrets.token_bytes(key_length)
    iv = secrets.token_bytes(iv_length)

    # Key and IV Length Validation
    assert len(key) == key_length, f"Generated key length ({len(key)}) does not match requested length ({key_length})."
    assert len(iv) == iv_length, f"Generated IV length ({len(iv)}) does not match requested length ({iv_length})."

    return key, iv


if __name__ == '__main__':
    # Example usage:
    key_length = 32  # Example key length (256 bits)
    iv_length = 16   # Example IV length (128 bits)

    try:
        key, iv = generate_secure_key_iv(key_length, iv_length)
        #print(f"Generated Key: {key.hex()}")  # Remove in production
        #print(f"Generated IV: {iv.hex()}")   # Remove in production

        # Generate a random salt (optional)
        salt = secrets.token_bytes(16)

        fingerprint = generate_fingerprint(key, iv, salt)
        print(f"Fingerprint: {fingerprint}")

    except ValueError as e:
        print(f"ValueError: {e}")
    except TypeError as e:
        print(f"TypeError: {e}")

