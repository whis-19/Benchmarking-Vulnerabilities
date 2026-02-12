import hmac
import hashlib
import os

# Recommended key length for HMAC-SHA256 is at least 32 bytes (256 bits)
# Generate a strong, random key using os.urandom()
# Store this key securely (e.g., in an encrypted configuration file)
# NEVER hardcode keys directly in the code.  This is just for demonstration.
# In a real application, load this key from a secure location.
# key = os.urandom(32)  # Example: Generate a 32-byte key
# For demonstration purposes, we'll use a hardcoded key, but this is NOT secure.
key = b"e179017a-62b0-4996-8a38-e91aa9f1"  # Replace with a securely generated and stored key
msg = b"Test"


def sign(pre_key, imsg, alg=hashlib.sha256):  # Default to SHA256
    """
    Signs a message using HMAC.

    Args:
        pre_key: The secret key (bytes).
        imsg: The message to sign (bytes).
        alg: The hashing algorithm to use (e.g., hashlib.sha256, hashlib.sha512).

    Returns:
        The HMAC signature (bytes).
    """
    return hmac.new(pre_key, imsg, alg).digest()


def verify(msg, sig, pre_key, alg=hashlib.sha256):
    """
    Verifies the signature of a message using HMAC.

    Args:
        msg: The message (bytes).
        sig: The signature to verify (bytes).
        pre_key: The secret key (bytes).
        alg: The hashing algorithm used for signing (e.g., hashlib.sha256).

    Returns:
        True if the signature is valid, False otherwise.
    """
    expected_sig = hmac.new(pre_key, msg, alg).digest()
    return hmac.compare_digest(sig, expected_sig)


def hash_password(password, salt=None):
    """
    Hashes a password using PBKDF2HMAC for strong password hashing.

    Args:
        password: The password to hash (string).
        salt: Optional salt (bytes). If None, a new salt is generated.

    Returns:
        A tuple containing the salt (bytes) and the hash (bytes).
    """
    if salt is None:
        salt = os.urandom(16)  # Generate a random salt
    
    # Use PBKDF2HMAC for strong password hashing
    hashed_password = hashlib.pbkdf2_hmac(
        'sha256',  # The hash digest algorithm for HMAC
        password.encode('utf-8'),  # Convert the password to bytes
        salt,  # Provide the salt
        100000  # It is recommended to use at least 100000 iterations of SHA256
    )
    return salt, hashed_password


def verify_password(password, salt, hashed_password):
    """
    Verifies a password against a stored hash using PBKDF2HMAC.

    Args:
        password: The password to verify (string).
        salt: The salt used to hash the password (bytes).
        hashed_password: The stored hash (bytes).

    Returns:
        True if the password is correct, False otherwise.
    """
    new_hash = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt,
        100000
    )
    return hmac.compare_digest(hashed_password, new_hash)


# Example Usage (HMAC):
signature = sign(key, msg)
is_valid = verify(msg, signature, key)
print(f"Signature: {signature.hex()}")
print(f"Signature is valid: {is_valid}")


# Example Usage (Password Hashing):
password = "my_secret_password"
salt, password_hash = hash_password(password)

# Store the salt and password_hash securely (e.g., in a database)
# NEVER store the password in plaintext!

# Verification:
password_to_check = "my_secret_password"
is_password_correct = verify_password(password_to_check, salt, password_hash)
print(f"Password is correct: {is_password_correct}")

wrong_password = "wrong_password"
is_wrong_password_correct = verify_password(wrong_password, salt, password_hash)
print(f"Wrong password is correct: {is_wrong_password_correct}")


# Secure Key Storage (Illustrative - Replace with a real implementation):
# In a real application, you would store the key in an encrypted file or a secure vault.
# For example, using cryptography library:
# from cryptography.fernet import Fernet
# def encrypt_key(key, encryption_key):
#     f = Fernet(encryption_key)
#     encrypted_key = f.encrypt(key)
#     return encrypted_key
#
# def decrypt_key(encrypted_key, encryption_key):
#     f = Fernet(encryption_key)
#     key = f.decrypt(encrypted_key)
#     return key

# Important Considerations:

# 1. Key Management:  The most critical aspect is secure key management.  Never hardcode keys.  Use a secure key management system (e.g., HashiCorp Vault, AWS KMS, Azure Key Vault) or encrypt the key at rest.

# 2. Salt Generation: Always use a unique, randomly generated salt for each password.  Store the salt alongside the password hash.

# 3. Iteration Count:  The iteration count for PBKDF2HMAC (or other key derivation functions) should be as high as possible without causing unacceptable performance delays.  100,000 is a good starting point, but increase it as hardware improves.

# 4. Algorithm Choice: SHA256 is a reasonable choice for PBKDF2HMAC, but consider SHA512 for even stronger security.

# 5. Storage: Store salts and password hashes in a database or configuration file with appropriate access controls.  Limit access to only the necessary users and processes.

# 6. Encryption:  If storing sensitive data (including keys or configuration files), encrypt them at rest using a strong encryption algorithm (e.g., AES).

# 7. Regular Key Rotation:  Implement a key rotation policy to periodically change the encryption keys.

# 8. Input Validation:  Always validate user input to prevent injection attacks.

# 9. Error Handling:  Handle errors gracefully and avoid revealing sensitive information in error messages.

# 10. Security Audits:  Regularly audit your code and infrastructure for security vulnerabilities.

