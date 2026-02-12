import os
import hashlib
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import secrets
import binascii
import re  # For password complexity validation

# --- Fernet Encryption/Decryption ---

def load_fernet_key():
    """
    Loads the Fernet key from the environment variable.
    If the key is not found, generates a new one and prints it to the console.
    WARNING: Printing the key to the console is only suitable for development.
             In production, use a secure secrets management solution.
             Consider using a temporary file storage mechanism (with appropriate file permissions)
             for development environments where environment variables are not easily managed.
             However, emphasize that this is *not* a production-ready solution.
    """
    key = os.environ.get("FERNET_KEY")
    if not key:
        key = Fernet.generate_key().decode()
        print(f"Generated Fernet key: {key}")
        print("WARNING: This key is printed to the console.  This is NOT secure for production.")
        print("Store this key securely in an environment variable or secrets management system.")
    return key

def encrypt_data(data: str, key: str) -> str:
    """Encrypts data using Fernet encryption."""
    f = Fernet(key.encode())
    encrypted_data = f.encrypt(data.encode())
    return encrypted_data.decode()

def decrypt_data(data: str, key: str) -> str:
    """Decrypts data using Fernet decryption."""
    f = Fernet(key.encode())
    decrypted_data = f.decrypt(data.encode())
    return decrypted_data.decode()


# --- Password Hashing ---

def generate_salt():
    """Generates a random salt."""
    return binascii.hexlify(os.urandom(16)).decode()

def hash_password(password: str, salt: str) -> str:
    """Hashes a password using PBKDF2-HMAC with a salt."""
    if not isinstance(password, str):
        raise TypeError("Password must be a string.")

    if not isinstance(salt, str):
        raise TypeError("Salt must be a string.")

    password_bytes = password.encode('utf-8')
    salt_bytes = salt.encode('utf-8')
    hashed_password = hashlib.pbkdf2_hmac('sha256', password_bytes, salt_bytes, 100000)  # Adjust iterations as needed
    return hashed_password.hex()

def verify_password(password: str, hashed_password: str, salt: str) -> bool:
    """Verifies a password against a stored hash."""
    if not isinstance(password, str):
        raise TypeError("Password must be a string.")

    if not isinstance(hashed_password, str):
        raise TypeError("Hashed password must be a string.")

    if not isinstance(salt, str):
        raise TypeError("Salt must be a string.")

    new_hash = hash_password(password, salt)
    return new_hash == hashed_password

# --- Password Complexity Requirements ---

def validate_password_complexity(password: str) -> bool:
    """
    Validates password complexity based on the following criteria:
    - Minimum length of 8 characters
    - At least one uppercase letter
    - At least one lowercase letter
    - At least one digit
    - At least one special character
    """
    if len(password) < 8:
        return False
    if not re.search(r"[A-Z]", password):
        return False
    if not re.search(r"[a-z]", password):
        return False
    if not re.search(r"[0-9]", password):
        return False
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False
    return True


# --- Example Usage ---
if __name__ == '__main__':
    # --- Fernet Encryption Example ---
    fernet_key = load_fernet_key()
    data = "Sensitive data to be encrypted"
    encrypted_data = encrypt_data(data, fernet_key)
    decrypted_data = decrypt_data(encrypted_data, fernet_key)

    print(f"Original data: {data}")
    print(f"Encrypted data: {encrypted_data}")
    print(f"Decrypted data: {decrypted_data}")
    print(f"Encryption and decryption successful: {data == decrypted_data}")

    # --- Password Hashing Example ---
    password = "my_Secret_password123!"
    if not validate_password_complexity(password):
        print("Password does not meet complexity requirements.")
    else:
        salt = generate_salt()  # Generate a unique salt for the user
        hashed = hash_password(password, salt)
        print(f"Hashed password: {hashed}")
        print(f"Salt: {salt}") # Store this salt with the hashed password

        is_valid = verify_password(password, hashed, salt)
        print(f"Password is valid: {is_valid}")

    # --- Rate Limiting (Illustrative - requires a framework like Flask) ---
    # In a real application, you would use a library like Flask-Limiter
    # to limit the number of login attempts from a single IP address.
    # This is just a placeholder to remind you to implement rate limiting.
    print("\nREMEMBER TO IMPLEMENT RATE LIMITING TO PREVENT BRUTE-FORCE ATTACKS!")
    print("Consider using a library like Flask-Limiter (if using Flask).")

    # --- Security Audit Reminder ---
    print("\nREMEMBER TO CONDUCT REGULAR SECURITY AUDITS TO IDENTIFY AND ADDRESS POTENTIAL VULNERABILITIES!")

