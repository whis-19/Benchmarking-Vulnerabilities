import hmac
import hashlib
import os

# Key should be securely generated and stored, not hardcoded.
# Example of generating a random key:
# key = os.urandom(32)  # 32 bytes for AES-256

# In a real application, store the key securely (e.g., in a configuration file
# with restricted access, or using a key management system).  Never hardcode
# keys in the source code.  The following is for demonstration purposes only.
key = b"e179017a-62b0-4996-8a38-e91aa9f1"  # Replace with secure key management

msg = b"Test"


def sign(pre_key, imsg, alg=hashlib.sha256):  # Default to SHA256
    """
    Signs a message using HMAC.

    Args:
        pre_key: The secret key (bytes).
        imsg: The message to sign (bytes).
        alg: The hashing algorithm to use (e.g., hashlib.sha256, hashlib.sha512).
             Defaults to SHA256.

    Returns:
        The HMAC signature (bytes).
    """
    return hmac.new(pre_key, imsg, alg).digest()


def verify(msg, sig, key, alg=hashlib.sha256):
    """
    Verifies the signature of the message using HMAC.

    Args:
        msg: The message (bytes).
        sig: The signature to verify (bytes).
        key: The secret key (bytes).
        alg: The hashing algorithm used for signing (e.g., hashlib.sha256).
             Defaults to SHA256.

    Returns:
        True if the signature is valid, False otherwise.
    """
    expected_sig = hmac.new(key, msg, alg).digest()
    return hmac.compare_digest(sig, expected_sig)


# Example usage:
signature = sign(key, msg)
is_valid = verify(msg, signature, key)

print(f"Signature: {signature.hex()}")
print(f"Signature is valid: {is_valid}")


# Example of password hashing and verification (using pbkdf2_hmac):

def hash_password(password, salt=None):
    """Hashes a password using PBKDF2-HMAC with a random salt."""
    if salt is None:
        salt = os.urandom(16)  # Generate a random salt
    
    # Use a strong hashing algorithm like SHA256 or SHA512
    hashed_password = hashlib.pbkdf2_hmac(
        'sha256',  # The hash digest algorithm for HMAC
        password.encode('utf-8'),  # Convert the password to bytes
        salt,  # Provide the salt
        100000  # It is recommended to use at least 100000 iterations of SHA256
    )
    return salt, hashed_password


def verify_password(password, salt, hashed_password):
    """Verifies a password against a stored hash and salt."""
    new_hash = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt,
        100000
    )
    return hmac.compare_digest(hashed_password, new_hash)


# Example password hashing and verification:
password = "my_secret_password"
salt, hashed_password = hash_password(password)

print(f"Salt: {salt.hex()}")
print(f"Hashed password: {hashed_password.hex()}")

is_password_valid = verify_password(password, salt, hashed_password)
print(f"Password is valid: {is_password_valid}")

wrong_password = "wrong_password"
is_wrong_password_valid = verify_password(wrong_password, salt, hashed_password)
print(f"Wrong password is valid: {is_wrong_password_valid}")

