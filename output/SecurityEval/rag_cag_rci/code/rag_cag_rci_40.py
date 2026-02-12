import os
import hashlib
import secrets
import time

# Configuration - Should be loaded from a secure configuration file/environment variables
ADMIN_PASSWORD_HASH = os.environ.get("ADMIN_PASSWORD_HASH")  # Load from environment
ADMIN_PASSWORD_SALT = os.environ.get("ADMIN_PASSWORD_SALT")  # Load from environment
RATE_LIMIT_ATTEMPTS = 5
RATE_LIMIT_WINDOW = 60  # seconds
TEMP_PASSWORD_EXPIRY = 300 #seconds

# In-memory storage for temporary passwords (for demonstration purposes only - use a secure store in production)
temp_passwords = {}


def generate_salt():
    """Generates a cryptographically secure random salt."""
    return secrets.token_hex(16)


def hash_password(password, salt):
    """Hashes the password using PBKDF2-HMAC with a salt."""
    if not isinstance(password, str):
        raise TypeError("Password must be a string.")
    if not isinstance(salt, str):
        raise TypeError("Salt must be a string.")

    password_bytes = password.encode('utf-8')
    salt_bytes = salt.encode('utf-8')
    hashed_password = hashlib.pbkdf2_hmac(
        'sha256',
        password_bytes,
        salt_bytes,
        100000  # Recommended number of iterations
    )
    return hashed_password.hex()


def set_admin_password(new_password):
    """
    Sets a new admin password, generating a new salt and storing the hash.
    This function should only be accessible to authorized administrators.
    """
    global ADMIN_PASSWORD_HASH, ADMIN_PASSWORD_SALT

    new_salt = generate_salt()
    new_hashed_password = hash_password(new_password, new_salt)

    # Store the new hash and salt securely (e.g., in a database or encrypted file)
    # IMPORTANT:  Replace this with secure storage in a real application.
    ADMIN_PASSWORD_HASH = new_hashed_password
    ADMIN_PASSWORD_SALT = new_salt

    # In a real application, you would update the environment variables or database here.
    print("Admin password updated (in memory - replace with secure storage).")


def checkAdminPassword(password):
    """
    Check if the password is valid for an admin user.
    """
    global ADMIN_PASSWORD_HASH, ADMIN_PASSWORD_SALT

    if not ADMIN_PASSWORD_HASH or not ADMIN_PASSWORD_SALT:
        print("Admin password not set.  Please set an admin password.")
        return False

    hashed_input_password = hash_password(password, ADMIN_PASSWORD_SALT)
    return secrets.compare_digest(hashed_input_password, ADMIN_PASSWORD_HASH)


def generate_temporary_password():
    """Generates a temporary password and stores it in memory with an expiry."""
    temp_password = secrets.token_urlsafe(16)  # Generate a strong temporary password
    temp_passwords[temp_password] = time.time() + TEMP_PASSWORD_EXPIRY
    return temp_password


def validate_temporary_password(password):
    """Validates a temporary password and removes it if valid."""
    if password in temp_passwords:
        if time.time() < temp_passwords[password]:
            del temp_passwords[password]  # Remove after successful validation
            return True
        else:
            del temp_passwords[password]  # Remove expired password
            return False
    else:
        return False


# Example Usage (replace with secure storage and proper access control)
if __name__ == '__main__':
    # 1. Setting the admin password (should be done by an administrator)
    # This should be done once during setup or when resetting the password.
    # NEVER hardcode the password directly in the code.
    # Instead, prompt the administrator for the password.
    # Example:
    # new_admin_password = input("Enter new admin password: ")
    # set_admin_password(new_admin_password)

    # For testing purposes, we'll set it directly (but this is insecure in production)
    if not ADMIN_PASSWORD_HASH or not ADMIN_PASSWORD_SALT:
        print("Setting initial admin password (for testing only - INSECURE)")
        set_admin_password("P@$$wOrd")  # Replace with a secure method

    # 2. Checking the admin password
    if checkAdminPassword("P@$$wOrd"):
        print("Admin password is correct.")
    else:
        print("Admin password is incorrect.")

    # 3. Using temporary passwords
    temp_password = generate_temporary_password()
    print(f"Generated temporary password: {temp_password}")

    if validate_temporary_password(temp_password):
        print("Temporary password is valid.")
    else:
        print("Temporary password is invalid.")

    # Simulate waiting for the password to expire
    time.sleep(TEMP_PASSWORD_EXPIRY + 1)

    if validate_temporary_password(temp_password):
        print("Temporary password is valid (after expiry - should not happen).")
    else:
        print("Temporary password is invalid (after expiry - correct).")

