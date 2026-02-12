import hashlib
import os
import secrets
import time

# Configuration - Should be managed externally (e.g., environment variables)
ADMIN_PASSWORD_HASH = None  # Initialize to None, loaded at startup
ADMIN_PASSWORD_SALT = None  # Initialize to None, loaded at startup
PASSWORD_UPDATE_INTERVAL = 86400  # 24 hours in seconds
LAST_PASSWORD_UPDATE = 0  # Timestamp of last password update

# Feature flag for hardcoded credential access
HARDCODED_CREDENTIAL_FEATURE_ENABLED = True
ALLOWED_USERS_FOR_HARDCODED_FEATURE = ["admin", "security_auditor"]  # Example

def initialize_admin_password():
    """
    Initializes the admin password hash and salt.  This should be called
    once at application startup.  It checks if a password already exists;
    if not, it prompts for a new one.  This addresses the "first login"
    requirement.
    """
    global ADMIN_PASSWORD_HASH, ADMIN_PASSWORD_SALT, LAST_PASSWORD_UPDATE

    if ADMIN_PASSWORD_HASH is None or ADMIN_PASSWORD_SALT is None:
        # No password set, prompt for a new one
        new_password = input("No admin password set. Please enter a strong password: ")
        if not new_password:
            raise ValueError("Password cannot be empty.")

        ADMIN_PASSWORD_SALT = secrets.token_hex(16)  # Generate a random salt
        ADMIN_PASSWORD_HASH = hash_password(new_password, ADMIN_PASSWORD_SALT)
        LAST_PASSWORD_UPDATE = time.time()
        print("Admin password initialized.")
    else:
        print("Admin password already initialized.")


def hash_password(password, salt):
    """
    Hashes the password using PBKDF2-HMAC with a random salt.
    """
    # Use PBKDF2-HMAC for strong password hashing
    password_bytes = password.encode('utf-8')
    salt_bytes = salt.encode('utf-8')
    hashed_password = hashlib.pbkdf2_hmac(
        'sha256',  # Use SHA256
        password_bytes,
        salt_bytes,
        100000  # Number of iterations - adjust for security/performance tradeoff
    )
    return hashed_password.hex()


def checkAdminPassword(password):
    """
    Checks if the provided password is valid for the admin user.
    """
    global ADMIN_PASSWORD_HASH, ADMIN_PASSWORD_SALT, LAST_PASSWORD_UPDATE

    # Check if the password needs to be updated
    if time.time() - LAST_PASSWORD_UPDATE > PASSWORD_UPDATE_INTERVAL:
        print("Admin password needs to be updated.")
        return False  # Force password update

    if ADMIN_PASSWORD_HASH is None or ADMIN_PASSWORD_SALT is None:
        print("Admin password not initialized.  Call initialize_admin_password() first.")
        return False

    # Hash the provided password with the stored salt
    hashed_attempt = hash_password(password, ADMIN_PASSWORD_SALT)

    # Compare the generated hash with the stored hash
    return secrets.compare_digest(hashed_attempt, ADMIN_PASSWORD_HASH)


def update_admin_password(new_password):
    """
    Updates the admin password.  Requires the current password for verification.
    """
    global ADMIN_PASSWORD_HASH, ADMIN_PASSWORD_SALT, LAST_PASSWORD_UPDATE

    current_password = input("Enter current admin password: ")
    if not checkAdminPassword(current_password):
        print("Incorrect current password.")
        return False

    if not new_password:
        print("New password cannot be empty.")
        return False

    ADMIN_PASSWORD_SALT = secrets.token_hex(16)  # Generate a new random salt
    ADMIN_PASSWORD_HASH = hash_password(new_password, ADMIN_PASSWORD_SALT)
    LAST_PASSWORD_UPDATE = time.time()
    print("Admin password updated successfully.")
    return True


def access_hardcoded_credential_feature(user):
    """
    Example function demonstrating access control for a feature controlled by
    hardcoded credentials (simulated).
    """
    if not HARDCODED_CREDENTIAL_FEATURE_ENABLED:
        print("Hardcoded credential feature is disabled.")
        return False

    if user not in ALLOWED_USERS_FOR_HARDCODED_FEATURE:
        print(f"User '{user}' is not authorized to access this feature.")
        return False

    print(f"User '{user}' is authorized to access the hardcoded credential feature.")
    # In a real application, this is where you would use the hardcoded
    # credentials (carefully!) to perform the desired action.
    return True


# Example Usage (Illustrative - replace with proper application logic)
if __name__ == '__main__':
    # Initialize the admin password at startup
    initialize_admin_password()

    # Example of checking the admin password
    if checkAdminPassword("correct_password"):  # Replace with the actual password
        print("Admin password is correct.")
    else:
        print("Admin password is incorrect.")

    # Example of updating the admin password
    # update_admin_password("new_strong_password")

    # Example of accessing a feature controlled by hardcoded credentials
    access_hardcoded_credential_feature("admin")
    access_hardcoded_credential_feature("unauthorized_user")

