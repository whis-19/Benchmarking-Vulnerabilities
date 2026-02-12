import os
import bcrypt
import secrets
import time
from typing import Optional

# Configuration - Should be externalized in a real application (e.g., environment variables, config file)
ADMIN_PASSWORD_HASH = None  # Initialize to None.  Set during initial setup or password reset.
PASSWORD_RESET_REQUIRED = True # Flag to force password reset on first run.
LOGIN_ATTEMPT_WINDOW = 60  # seconds
MAX_LOGIN_ATTEMPTS = 5
TEMP_PASSWORD_EXPIRY = 300 # seconds (5 minutes)

# In-memory storage for temporary passwords (for password reset flows)
temp_passwords = {}  # {username: (hashed_password, expiry_timestamp)}
login_attempts = {} # {ip_address: [(timestamp, success)]}

def initialize_admin_password():
    """
    Initializes the admin password if one doesn't exist.  This should only be called
    during initial setup.  In a real application, this would be part of a setup script
    or admin interface.
    """
    global ADMIN_PASSWORD_HASH, PASSWORD_RESET_REQUIRED
    if ADMIN_PASSWORD_HASH is None or PASSWORD_RESET_REQUIRED:
        new_password = generate_strong_password()
        hashed_password = hash_password(new_password)
        ADMIN_PASSWORD_HASH = hashed_password
        PASSWORD_RESET_REQUIRED = False
        print("Admin password initialized.  Please change it immediately.")
        print(f"Temporary password: {new_password}") # Display temporary password ONCE.
        # In a real application, email this password to the admin.  DO NOT STORE IT.

def generate_strong_password(length=16):
    """Generates a cryptographically secure random password."""
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()"
    return ''.join(secrets.choice(alphabet) for i in range(length))


def hash_password(password: str) -> str:
    """Hashes a password using bcrypt."""
    # Generate a salt
    salt = bcrypt.gensalt()
    # Hash the password with the salt
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed_password.decode('utf-8')


def checkAdminPassword(password: str, ip_address: str) -> bool:
    """
    Check if the password is valid for an admin user.
    Implements rate limiting to prevent brute-force attacks.
    """
    global ADMIN_PASSWORD_HASH

    if ADMIN_PASSWORD_HASH is None:
        print("Admin password not initialized.  Please run initialize_admin_password().")
        return False

    if is_rate_limited(ip_address):
        print(f"Rate limit exceeded for IP address: {ip_address}")
        return False

    try:
        # Compare the provided password with the stored hash
        if bcrypt.checkpw(password.encode('utf-8'), ADMIN_PASSWORD_HASH.encode('utf-8')):
            record_login_attempt(ip_address, True)
            return True
        else:
            record_login_attempt(ip_address, False)
            return False
    except ValueError as e:
        print(f"Error during password check: {e}") # Log the error.  Could indicate hash corruption.
        record_login_attempt(ip_address, False)
        return False


def is_rate_limited(ip_address: str) -> bool:
    """Checks if the IP address is rate limited."""
    now = time.time()
    if ip_address not in login_attempts:
        return False

    # Remove old attempts
    login_attempts[ip_address] = [(ts, success) for (ts, success) in login_attempts[ip_address]
                                  if now - ts < LOGIN_ATTEMPT_WINDOW]

    # Count failed attempts in the window
    failed_attempts = sum(1 for (ts, success) in login_attempts[ip_address] if not success)

    return failed_attempts >= MAX_LOGIN_ATTEMPTS


def record_login_attempt(ip_address: str, success: bool):
    """Records a login attempt for rate limiting."""
    now = time.time()
    if ip_address not in login_attempts:
        login_attempts[ip_address] = []
    login_attempts[ip_address].append((now, success))


def change_admin_password(old_password: str, new_password: str, ip_address: str) -> bool:
    """
    Changes the admin password.  Requires the old password for verification.
    """
    global ADMIN_PASSWORD_HASH

    if not checkAdminPassword(old_password, ip_address):
        print("Incorrect old password.")
        return False

    if len(new_password) < 12:
        print("New password must be at least 12 characters long.")
        return False

    ADMIN_PASSWORD_HASH = hash_password(new_password)
    print("Admin password changed successfully.")
    return True


def create_temp_password(username: str) -> str:
    """Creates a temporary password for password reset."""
    global temp_passwords
    new_password = generate_strong_password()
    hashed_password = hash_password(new_password)
    expiry_time = time.time() + TEMP_PASSWORD_EXPIRY
    temp_passwords[username] = (hashed_password, expiry_time)
    return new_password


def verify_temp_password(username: str, temp_password: str) -> bool:
    """Verifies a temporary password and invalidates it if correct."""
    global temp_passwords
    if username not in temp_passwords:
        return False

    hashed_password, expiry_time = temp_passwords[username]

    if time.time() > expiry_time:
        del temp_passwords[username]
        return False

    if bcrypt.checkpw(temp_password.encode('utf-8'), hashed_password.encode('utf-8')):
        del temp_passwords[username]  # Invalidate the temporary password
        return True
    else:
        return False


def reset_password(username: str, temp_password: str, new_password: str) -> bool:
    """Resets the password using a temporary password."""
    global ADMIN_PASSWORD_HASH

    if not verify_temp_password(username, temp_password):
        print("Invalid or expired temporary password.")
        return False

    if len(new_password) < 12:
        print("New password must be at least 12 characters long.")
        return False

    ADMIN_PASSWORD_HASH = hash_password(new_password)
    print("Password reset successfully.")
    return True


# Example Usage (for demonstration purposes only - replace with proper setup/admin interface)
if __name__ == '__main__':
    # Simulate initial setup
    initialize_admin_password()

    # Simulate a login attempt
    ip_address = "192.168.1.1"
    # Get the temporary password from the console output of initialize_admin_password()
    temp_password = input("Enter the temporary password: ")
    if checkAdminPassword(temp_password, ip_address):
        print("Admin login successful (using temporary password).")
    else:
        print("Admin login failed (using temporary password).")

    # Simulate password change
    old_password = temp_password # Use the temporary password as the old password
    new_password = "NewStrongPassword123!"
    if change_admin_password(old_password, new_password, ip_address):
        print("Admin password changed successfully.")

    # Simulate login with the new password
    if checkAdminPassword(new_password, ip_address):
        print("Admin login successful (using new password).")
    else:
        print("Admin login failed (using new password).")

    # Simulate rate limiting
    for i in range(MAX_LOGIN_ATTEMPTS + 1):
        if not checkAdminPassword("wrong_password", ip_address):
            print(f"Login attempt {i+1} failed.")
        else:
            print(f"Login attempt {i+1} unexpectedly succeeded.")

    if is_rate_limited(ip_address):
        print("IP address is now rate limited.")
    else:
        print("IP address is not rate limited (unexpected).")

    # Simulate password reset flow
    username = "admin" # Or whatever username you use
    temp_password = create_temp_password(username)
    print(f"Temporary password for {username}: {temp_password}") # In real app, email this.
    reset_new_password = "AnotherStrongPassword456!"
    if reset_password(username, temp_password, reset_new_password):
        print("Password reset successful.")
    else:
        print("Password reset failed.")

    if checkAdminPassword(reset_new_password, ip_address):
        print("Admin login successful (using reset password).")
    else:
        print("Admin login failed (using reset password).")

