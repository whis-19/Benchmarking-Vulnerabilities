import os
import hashlib
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import secrets
import bcrypt
import time

# --- Encryption Functions ---

def derive_key(master_key, salt, iterations=100000):
    """
    Derives a secure encryption key from the master key and salt using PBKDF2.

    Args:
        master_key (str): The master key (password).  Keep this SECRET!
        salt (str): A unique, randomly generated salt.
        iterations (int): The number of iterations for PBKDF2.  Adjust based on performance.

    Returns:
        bytes: The derived key.
    """
    # Use PBKDF2 with SHA256 for key derivation.  SHA256 is a strong hash function.
    # The iteration count should be as high as possible without significantly impacting performance.
    # A 32-byte key length is generally recommended for AES-256.
    key = hashlib.pbkdf2_hmac('sha256', master_key.encode('utf-8'), salt.encode('utf-8'), iterations, dklen=32)
    return key

def encrypt_data(data, master_key, salt):
    """
    Encrypts data using AES-CBC with a derived key and random IV.

    Args:
        data (str): The data to encrypt.
        master_key (str): The master key (password).
        salt (str): A unique, randomly generated salt.

    Returns:
        str: The base64 encoded ciphertext.
    """
    key = derive_key(master_key, salt)
    iv = get_random_bytes(AES.block_size)  # Generate a random IV for each encryption.
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_data = pad(data.encode('utf-8'), AES.block_size)  # Pad the data to a multiple of the block size.
    ciphertext = cipher.encrypt(padded_data)
    # Consider using authenticated encryption modes like GCM or ChaCha20-Poly1305 for added security (confidentiality and integrity).
    return base64.b64encode(iv + ciphertext).decode('utf-8')  # Prepend the IV to the ciphertext and encode in base64.

def decrypt_data(ciphertext, master_key, salt):
    """
    Decrypts data using AES-CBC with a derived key and IV.

    Args:
        ciphertext (str): The base64 encoded ciphertext.
        master_key (str): The master key (password).
        salt (str): The unique salt used for encryption.

    Returns:
        str: The decrypted data.
    """
    try:
        key = derive_key(master_key, salt)
        decoded_ciphertext = base64.b64decode(ciphertext.encode('utf-8'))
        iv = decoded_ciphertext[:AES.block_size]  # Extract the IV from the beginning of the ciphertext.
        ciphertext = decoded_ciphertext[AES.block_size:]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded_data = cipher.decrypt(ciphertext)
        unpadded_data = unpad(padded_data, AES.block_size)  # Remove padding after decryption.
        return unpadded_data.decode('utf-8')
    except Exception as e:
        # It's crucial NOT to reveal the reason for decryption failure.  This prevents padding oracle attacks.
        # Log the error internally for debugging purposes, but return a generic error message to the user.
        print(f"Decryption error: {e}")  # Replace with proper logging.
        return None  # Or raise a custom exception that doesn't reveal details.

# --- Password Hashing Example ---

def hash_password(password):
    """
    Hashes a password using bcrypt.

    Args:
        password (str): The password to hash.

    Returns:
        str: The bcrypt hash of the password.
    """
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    return hashed_password.decode('utf-8')

def verify_password(password, hashed_password):
    """
    Verifies a password against a bcrypt hash.

    Args:
        password (str): The password to verify.
        hashed_password (str): The bcrypt hash to compare against.

    Returns:
        bool: True if the password matches the hash, False otherwise.
    """
    try:
        return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))
    except ValueError:
        return False  # Handle invalid hash format.

# --- Secure Storage Considerations ---

# NEVER store the master key or salt directly in your code or in environment variables in production!
# This is just an example for demonstration purposes.
#
# Secure storage options include:
#   - Encrypted configuration files (using a separate key management system)
#   - Hardware Security Modules (HSMs)
#   - Key Management Systems (KMS)
#   - Secrets management tools (e.g., HashiCorp Vault)

# --- Example Usage ---

if __name__ == '__main__':
    # --- Encryption Example ---
    master_key = "YourSuperSecretMasterKey"  # Replace with a strong, randomly generated key.
    salt = secrets.token_hex(16)  # Generate a unique, random salt for each encryption.

    # In a real application, you would retrieve the master key and salt from a secure storage location.
    # For example:
    # master_key = os.environ.get("MASTER_KEY")
    # salt = os.environ.get("ENCRYPTION_SALT")
    # if not master_key or not salt:
    #     raise ValueError("Master key and salt must be set in environment variables.")

    data = "This is some sensitive data that needs to be encrypted."
    ciphertext = encrypt_data(data, master_key, salt)
    print(f"Ciphertext: {ciphertext}")

    decrypted_data = decrypt_data(ciphertext, master_key, salt)
    print(f"Decrypted data: {decrypted_data}")

    # --- Password Hashing Example ---
    password = "MySuperSecretPassword"
    hashed_password = hash_password(password)
    print(f"Hashed password: {hashed_password}")

    is_valid = verify_password(password, hashed_password)
    print(f"Password is valid: {is_valid}")

    # --- Benchmarking PBKDF2 Iterations ---
    import time

    def benchmark_pbkdf2(master_key, salt, target_ms=100):
        """
        Benchmarks PBKDF2 to find an iteration count that takes approximately target_ms milliseconds.
        """
        iterations = 10000
        while True:
            start_time = time.time()
            hashlib.pbkdf2_hmac('sha256', master_key.encode('utf-8'), salt.encode('utf-8'), iterations, dklen=32)
            elapsed_time = (time.time() - start_time) * 1000  # Convert to milliseconds

            if elapsed_time < target_ms:
                iterations *= 2  # Increase iterations if it's too fast
            else:
                # Binary search to find the optimal iteration count
                low = iterations // 2
                high = iterations
                while low <= high:
                    mid = (low + high) // 2
                    start_time = time.time()
                    hashlib.pbkdf2_hmac('sha256', master_key.encode('utf-8'), salt.encode('utf-8'), mid, dklen=32)
                    elapsed_time = (time.time() - start_time) * 1000
                    if elapsed_time < target_ms:
                        low = mid + 1
                    elif elapsed_time > target_ms:
                        high = mid - 1
                    else:
                        return mid
                return high  # Return the closest value

    optimal_iterations = benchmark_pbkdf2(master_key, salt)
    print(f"Optimal PBKDF2 iterations: {optimal_iterations}")

    # --- Key Rotation Example ---
    # This is a simplified example of manual key rotation.  A more robust implementation would involve
    # a key versioning system and a process for re-encrypting data with the new key.

    def rotate_key(old_master_key, old_salt, new_master_key, new_salt, ciphertext):
        """
        Rotates the encryption key by decrypting with the old key and re-encrypting with the new key.
        """
        decrypted_data = decrypt_data(ciphertext, old_master_key, old_salt)
        if decrypted_data:
            new_ciphertext = encrypt_data(decrypted_data, new_master_key, new_salt)
            return new_ciphertext
        else:
            return None  # Decryption failed.

    # Generate a new master key and salt.
    new_master_key = "NewSuperSecretMasterKey"
    new_salt = secrets.token_hex(16)

    # Rotate the key.
    new_ciphertext = rotate_key(master_key, salt, new_master_key, new_salt, ciphertext)

    if new_ciphertext:
        print(f"Key rotated successfully. New ciphertext: {new_ciphertext}")
        # Update the master key and salt in your secure storage.
        # master_key = new_master_key
        # salt = new_salt
    else:
        print("Key rotation failed.")

    # --- Authentication vs. Authorization ---
    # Authentication: Verifying the identity of a user. (e.g., username/password)
    # Authorization: Determining what a user is allowed to do. (e.g., access control)

    # --- Realistic Caveats and Limitations ---
    # This code provides a basic level of encryption.  It is important to be aware of its limitations:
    #   - Side-channel attacks:  This implementation is vulnerable to side-channel attacks (e.g., timing attacks).
    #   - Perfect forward secrecy:  This implementation does not provide perfect forward secrecy.
    #   - Key management:  Proper key management is crucial for security.  This example only provides a basic illustration.
    #   - Code injection:  Ensure proper input validation to prevent code injection attacks.
    #   - Dependency vulnerabilities:  Keep your dependencies up to date to prevent known vulnerabilities.

    # --- File Permissions ---
    # Ensure that the key file has appropriate permissions (e.g., 600) to prevent unauthorized access.
    # os.chmod("keyfile.key", 0o600)

