import hmac
import hashlib
import os

# Key management:  In a real application, the key should be:
# 1.  Generated securely (e.g., using os.urandom())
# 2.  Stored securely (e.g., in a hardware security module, encrypted configuration file, or secrets management system)
# 3.  Rotated regularly (as per guideline 6)
# For demonstration purposes, we'll use a randomly generated key.  NEVER hardcode keys in production.
# key = b"e179017a-62b0-4996-8a38-e91aa9f1"  # Insecure: Hardcoded key
key = os.urandom(32)  # Secure: Randomly generated key (256 bits)

# Example message
msg = b"Test"


def sign(pre_key, imsg, alg=hashlib.sha256):  # Use SHA256 by default (stronger)
    """
    Signs a message using HMAC.

    Args:
        pre_key: The secret key (bytes).
        imsg: The message to sign (bytes).
        alg: The hashing algorithm to use (e.g., hashlib.sha256, hashlib.sha512).  Defaults to SHA256.

    Returns:
        The HMAC signature (bytes).
    """
    return hmac.new(pre_key, imsg, alg).digest()


def verify(message, signature, pre_key, alg=hashlib.sha256):
    """
    Verifies the HMAC signature of a message.

    Args:
        message: The message to verify (bytes).
        signature: The HMAC signature to check (bytes).
        pre_key: The secret key (bytes).
        alg: The hashing algorithm used for signing (e.g., hashlib.sha256). Defaults to SHA256.

    Returns:
        True if the signature is valid, False otherwise.
    """
    expected_signature = hmac.new(pre_key, message, alg).digest()
    return hmac.compare_digest(signature, expected_signature)  # Secure comparison


def hash_password(password, salt=None):
    """Hashes a password using PBKDF2HMAC with a randomly generated salt.

    Args:
        password: The password to hash (string).
        salt: Optional salt to use. If None, a new salt is generated.

    Returns:
        A tuple containing the salt (bytes) and the hash (bytes).
    """
    if salt is None:
        salt = os.urandom(16)  # Generate a random salt (128 bits)
    
    # Use PBKDF2HMAC for password hashing (Guideline 8)
    hashed_password = hashlib.pbkdf2_hmac(
        'sha256',  # Use SHA256 for the HMAC
        password.encode('utf-8'),  # Convert password to bytes
        salt,
        100000  # Use a high number of iterations (at least 100000)
    )
    return salt, hashed_password


def verify_password(password, salt, hashed_password):
    """Verifies a password against a stored hash and salt.

    Args:
        password: The password to verify (string).
        salt: The salt used to hash the password (bytes).
        hashed_password: The stored hash of the password (bytes).

    Returns:
        True if the password is correct, False otherwise.
    """
    # Hash the provided password with the stored salt
    new_hash = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt,
        100000
    )
    # Use hmac.compare_digest for secure comparison (Guideline 11)
    return hmac.compare_digest(new_hash, hashed_password)


# Example Usage:
# Signing and Verification
signature = sign(key, msg)
is_valid = verify(msg, signature, key)
print(f"Signature: {signature.hex()}")
print(f"Signature is valid: {is_valid}")

# Password Hashing and Verification
password = "my_secret_password"
salt, password_hash = hash_password(password)

print(f"Salt: {salt.hex()}")
print(f"Password Hash: {password_hash.hex()}")

is_password_valid = verify_password(password, salt, password_hash)
print(f"Password is valid: {is_password_valid}")

wrong_password = "wrong_password"
is_wrong_password_valid = verify_password(wrong_password, salt, password_hash)
print(f"Wrong password is valid: {is_wrong_password_valid}")


# Example of storing sensitive information (passwords, keys) securely:
# In a real application, you would use a secure configuration file or database
# with restricted access.  This is just a placeholder.
def store_sensitive_data(data, filename="secrets.enc"):
    """Encrypts and stores sensitive data in a file.  This is a simplified example.
       In a real application, use a robust encryption library like cryptography.io.
    """
    # Generate a random encryption key (for demonstration only - use a proper key management system)
    encryption_key = os.urandom(32)
    from cryptography.fernet import Fernet
    f = Fernet(encryption_key)
    encrypted_data = f.encrypt(data.encode('utf-8'))

    with open(filename, "wb") as f:
        f.write(encryption_key) # Store the encryption key (INSECURE - for demonstration only)
        f.write(b"\n")
        f.write(encrypted_data)

def load_sensitive_data(filename="secrets.enc"):
    """Loads and decrypts sensitive data from a file.  This is a simplified example.
       In a real application, use a robust encryption library like cryptography.io.
    """
    try:
        with open(filename, "rb") as f:
            encryption_key = f.readline().strip()
            encrypted_data = f.read()
            from cryptography.fernet import Fernet
            f = Fernet(encryption_key)
            decrypted_data = f.decrypt(encrypted_data).decode('utf-8')
            return decrypted_data
    except FileNotFoundError:
        return None

# Example usage of secure storage (replace with a proper implementation)
sensitive_data = f"My secret key: {key.hex()}, My password hash: {password_hash.hex()}"
store_sensitive_data(sensitive_data)
loaded_data = load_sensitive_data()

if loaded_data:
    print(f"Loaded sensitive data: {loaded_data}")
else:
    print("No sensitive data found.")

