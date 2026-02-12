import hashlib
import os
from typing import Optional, Tuple

# Consider using a proper database for storing user credentials
# This is a simplified example for demonstration purposes only.
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD_HASH = "your_secure_admin_password_hash"  # Replace with a real hash!

HAS_ADMIN_ACCESS = False


def verify_password(password: str, hashed_password: str) -> bool:
    """Verifies a password against a stored hash using pbkdf2_hmac."""
    try:
        # Extract salt and iterations from the stored hash
        salt = hashed_password[:32]
        iterations = int(hashed_password[32:40])
        stored_hash = hashed_password[40:]

        # Hash the provided password with the same salt and iterations
        hashed_password_candidate = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt.encode('utf-8'),
            iterations
        ).hex()

        # Compare the generated hash with the stored hash
        return hashed_password_candidate == stored_hash
    except ValueError:
        # Handle cases where the stored hash is malformed
        return False


def hash_password(password: str) -> str:
    """Hashes a password using pbkdf2_hmac with a random salt."""
    salt = os.urandom(16).hex()
    iterations = 100000  # Adjust the number of iterations for security
    hashed_password = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt.encode('utf-8'),
        iterations
    ).hex()
    return salt + str(iterations).zfill(8) + hashed_password


def admin_access(request) -> Tuple[bool, str]:
    """
    Validates the username and password from the request for admin access.
    Sets the HAS_ADMIN_ACCESS flag if authentication is successful.

    Args:
        request:  A dictionary-like object representing the HTTP request.
                  It should contain 'username' and 'password' keys.

    Returns:
        A tuple: (bool, str)
            - bool: True if admin access is granted, False otherwise.
            - str:  A message indicating the outcome of the authentication.
    """
    global HAS_ADMIN_ACCESS  # Use the global variable

    username = request.get("username")
    password = request.get("password")

    if not username or not password:
        return False, "Username and password are required."

    if username == ADMIN_USERNAME:
        if verify_password(password, ADMIN_PASSWORD_HASH):
            HAS_ADMIN_ACCESS = True
            return True, "Admin access granted."
        else:
            return False, "Invalid password."
    else:
        return False, "Invalid username."


# Example usage (replace with your actual request object)
class MockRequest:
    def __init__(self, username, password):
        self.username = username
        self.password = password

    def get(self, key):
        if key == "username":
            return self.username
        elif key == "password":
            return self.password
        return None


if __name__ == '__main__':
    # Example of setting up a new admin password (only do this once!)
    # new_password = "MyStrongAdminPassword123!"
    # hashed_password = hash_password(new_password)
    # print(f"Hashed password for admin: {hashed_password}")
    # Store this hashed_password securely (e.g., in a database)

    # Example of a successful login
    request_success = MockRequest("admin", "MyStrongAdminPassword123!") # Replace with the actual password used to generate the hash
    ADMIN_PASSWORD_HASH = hash_password("MyStrongAdminPassword123!") # Replace with the actual password used to generate the hash
    access_granted, message = admin_access(request_success)
    print(f"Access granted: {access_granted}, Message: {message}")
    print(f"HAS_ADMIN_ACCESS: {HAS_ADMIN_ACCESS}")

    # Example of a failed login
    request_failure = MockRequest("admin", "wrong_password")
    access_granted, message = admin_access(request_failure)
    print(f"Access granted: {access_granted}, Message: {message}")
    print(f"HAS_ADMIN_ACCESS: {HAS_ADMIN_ACCESS}")  # Should still be True from the previous successful login (demonstrates the need for proper session management)

    request_failure_user = MockRequest("not_admin", "wrong_password")
    access_granted, message = admin_access(request_failure_user)
    print(f"Access granted: {access_granted}, Message: {message}")
    print(f"HAS_ADMIN_ACCESS: {HAS_ADMIN_ACCESS}") # Should still be True from the previous successful login (demonstrates the need for proper session management)

