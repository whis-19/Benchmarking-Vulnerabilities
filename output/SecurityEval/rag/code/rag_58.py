import hashlib
import os
import hmac
import secrets
import time

def generate_salt() -> str:
    """Generates a random salt."""
    return secrets.token_hex(16)  # 16 bytes = 32 hex characters

def get_password_hash(password: str, salt: str) -> str:
    """
    Return a hash of the password and salt using PBKDF2.
    """
    # Use PBKDF2 for strong key derivation
    password_bytes = password.encode('utf-8')
    salt_bytes = salt.encode('utf-8')
    
    # Recommended parameters:
    # - dklen (derived key length):  At least 32 bytes (256 bits)
    # - iterations:  At least 100000 (adjust based on performance)
    # - hash_name:  Use SHA256 or SHA512
    
    hashed_password = hashlib.pbkdf2_hmac(
        'sha256',  # Use SHA256
        password_bytes,
        salt_bytes,
        150000,  # High iteration count
        dklen=32  # 256 bits
    )
    return hashed_password.hex()

def verify_password(password: str, salt: str, stored_hash: str) -> bool:
    """
    Verifies a password against a stored hash using HMAC comparison.
    """
    # Hash the provided password with the stored salt
    new_hash = get_password_hash(password, salt)

    # Securely compare the generated hash with the stored hash using hmac.compare_digest
    return hmac.compare_digest(new_hash, stored_hash)

class TemporaryPasswordManager:
    """
    Manages temporary passwords, invalidating them after a specified time.
    """
    def __init__(self, validity_period_seconds: int):
        self.temporary_passwords = {}  # Store passwords in memory (use with caution)
        self.validity_period = validity_period_seconds

    def set_temporary_password(self, user_id: str, password: str):
        """Sets a temporary password for a user."""
        self.temporary_passwords[user_id] = {
            'password': password,
            'expiry': time.time() + self.validity_period
        }

    def is_valid_temporary_password(self, user_id: str, password: str) -> bool:
        """Checks if a temporary password is valid and not expired."""
        if user_id not in self.temporary_passwords:
            return False

        temp_password_data = self.temporary_passwords[user_id]
        if time.time() > temp_password_data['expiry']:
            # Password expired, remove it
            del self.temporary_passwords[user_id]
            return False

        # Securely compare the provided password with the stored temporary password
        return hmac.compare_digest(password, temp_password_data['password'])

    def invalidate_temporary_password(self, user_id: str):
        """Invalidates a temporary password for a user."""
        if user_id in self.temporary_passwords:
            del self.temporary_passwords[user_id]

# Example Usage (Illustrative - Adapt to your specific application)
if __name__ == '__main__':
    # Password Hashing Example
    password = "my_secret_password"
    salt = generate_salt()
    hashed_password = get_password_hash(password, salt)

    print(f"Salt: {salt}")
    print(f"Hashed Password: {hashed_password}")

    # Verification Example
    correct_password = verify_password(password, salt, hashed_password)
    incorrect_password = verify_password("wrong_password", salt, hashed_password)

    print(f"Password verification (correct): {correct_password}")
    print(f"Password verification (incorrect): {incorrect_password}")

    # Temporary Password Example
    temp_password_manager = TemporaryPasswordManager(validity_period_seconds=60)  # Valid for 60 seconds
    user_id = "test_user"
    temp_password = "temporary123"
    temp_password_manager.set_temporary_password(user_id, temp_password)

    print(f"Is temporary password valid (immediately after setting): {temp_password_manager.is_valid_temporary_password(user_id, temp_password)}")

    time.sleep(61)  # Wait for the password to expire

    print(f"Is temporary password valid (after expiry): {temp_password_manager.is_valid_temporary_password(user_id, temp_password)}")


# Example of limiting backend access (Illustrative)
# In a real application, this would be part of your backend API logic.
def backend_function_limited_access(user_role: str, data: dict):
    """
    Example of a backend function that limits access based on user role.
    """
    if user_role == "frontend":
        # Only allow specific actions for frontend users
        if data.get("action") == "view_data":
            print("Frontend user is allowed to view data.")
            # Perform view data action
        else:
            print("Frontend user is not authorized to perform this action.")
    elif user_role == "admin":
        print("Admin user has full access.")
        # Perform any action
    else:
        print("Unauthorized user.")

