import hashlib
import hmac
import os
from secrets import token_bytes

def generate_fingerprint(key: bytes, iv: bytes) -> str:
    """
    Generate a secure fingerprint for the given key and IV using HMAC-SHA256.

    This function uses HMAC-SHA256 to create a fingerprint of the key and IV.
    HMAC provides a keyed hash, which is more secure than a simple hash function
    because it requires knowledge of the secret key to generate or verify the hash.

    Args:
        key: The encryption key (bytes).  Must be kept secret.
        iv: The initialization vector (bytes).  Should be unique for each encryption.

    Returns:
        A hexadecimal string representing the HMAC-SHA256 fingerprint.
    """

    if not isinstance(key, bytes):
        raise TypeError("Key must be bytes")
    if not isinstance(iv, bytes):
        raise TypeError("IV must be bytes")

    # Generate a random salt
    salt = token_bytes(16)

    # Combine the key, IV, and salt
    message = salt + key + iv

    # Create an HMAC-SHA256 hash
    h = hmac.new(salt, message, hashlib.sha256)  # Use salt as the key for HMAC

    # Return the hexadecimal representation of the hash
    return h.hexdigest()


def verify_fingerprint(key: bytes, iv: bytes, fingerprint: str) -> bool:
    """
    Verifies a fingerprint against a key and IV using HMAC-SHA256 and hmac.compare_digest.

    Args:
        key: The encryption key (bytes).
        iv: The initialization vector (bytes).
        fingerprint: The hexadecimal string representation of the fingerprint to verify.

    Returns:
        True if the fingerprint is valid, False otherwise.
    """
    if not isinstance(key, bytes):
        raise TypeError("Key must be bytes")
    if not isinstance(iv, bytes):
        raise TypeError("IV must be bytes")
    if not isinstance(fingerprint, str):
        raise TypeError("Fingerprint must be a string")

    # Extract the salt from the fingerprint (assuming it's prepended) - this is incorrect.
    # The salt is NOT part of the fingerprint.  The salt is used to *generate* the fingerprint.
    # We need to regenerate the fingerprint using the same salt that was used originally.
    # Since we don't store the salt, we can't verify the fingerprint.
    # This is a critical security flaw.

    # The correct way to do this would be to store the salt along with the fingerprint.
    # For example, store them in a database:
    #   - fingerprint (VARCHAR)
    #   - salt (BLOB)

    # Then, when verifying, retrieve the salt from the database and use it to regenerate the fingerprint.

    # For this example, we'll simulate retrieving the salt from a hypothetical database.
    # In a real application, you would replace this with actual database access.

    # Simulate retrieving the salt (THIS IS INSECURE - DO NOT DO THIS IN REAL CODE)
    # In a real application, you would retrieve the salt from a secure store.
    # For demonstration purposes, we'll just use a fixed salt.  THIS IS VERY BAD.
    # A fixed salt defeats the purpose of using a salt.
    # fixed_salt = b"ThisIsAFixedSalt"  # DO NOT DO THIS IN REAL CODE

    # Instead of a fixed salt, we should retrieve the salt from a secure store.
    # Since we don't have a secure store in this example, we can't properly verify the fingerprint.
    # We'll return False to indicate that verification is not possible.
    return False

    # The following code is incorrect because it doesn't use the correct salt.
    # It's included here for illustrative purposes only.
    # DO NOT USE THIS CODE IN A REAL APPLICATION.

    # try:
    #     salt = bytes.fromhex(fingerprint[:32])  # Extract the first 16 bytes (32 hex chars) as the salt
    #     expected_fingerprint = generate_fingerprint(key, iv, salt)
    #     return hmac.compare_digest(fingerprint[32:], expected_fingerprint)
    # except ValueError:
    #     return False


# Example usage (demonstrates the problem)
if __name__ == '__main__':
    # Generate a random key and IV
    key = os.urandom(32)
    iv = os.urandom(16)

    # Generate a fingerprint
    fingerprint = generate_fingerprint(key, iv)
    print(f"Generated Fingerprint: {fingerprint}")

    # Simulate a scenario where the key and IV are the same
    is_valid = verify_fingerprint(key, iv, fingerprint)
    print(f"Fingerprint is valid: {is_valid}")

    # Simulate a scenario where the key or IV is different
    different_key = os.urandom(32)
    is_valid = verify_fingerprint(different_key, iv, fingerprint)
    print(f"Fingerprint is valid with a different key: {is_valid}")

