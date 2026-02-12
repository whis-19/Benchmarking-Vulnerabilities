import hashlib
import os
import secrets
import re
from typing import List, Union

# --- Authentication & Authorization ---

def hash_password(password: str, salt: bytes = None) -> tuple[bytes, bytes]:
    """Hashes a password using PBKDF2-HMAC-SHA256.

    Args:
        password: The password to hash.
        salt: Optional salt. If None, a new salt is generated.

    Returns:
        A tuple containing the salt and the hash.
    """
    if salt is None:
        salt = os.urandom(16)  # Generate a random salt
    
    # Use a strong iteration count
    iterations = 100000  # Adjust as needed for performance/security tradeoff
    
    hashed_password = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt,
        iterations
    )
    return salt, hashed_password


def verify_password(password: str, salt: bytes, hashed_password: bytes) -> bool:
    """Verifies a password against a stored hash.

    Args:
        password: The password to verify.
        salt: The salt used to hash the stored password.
        hashed_password: The stored hash.

    Returns:
        True if the password matches the hash, False otherwise.
    """
    try:
        new_hash = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt,
            100000  # Must match the iteration count used during hashing
        )
        return secrets.compare_digest(new_hash, hashed_password)
    except ValueError:
        return False  # Handle potential length mismatch


# --- Input Validation ---

def is_valid_integer(input_str: str) -> bool:
    """Validates if a string is a valid integer."""
    pattern = r"^-?\d+$"  # Allows for optional negative sign
    return bool(re.match(pattern, input_str))


# --- Secure Array Access ---

def get_array_value(data: List[Union[int, str, float]], index_str: str) -> Union[int, str, float, str]:
    """
    Safely retrieves a value from an array based on user-provided index.

    Args:
        data: The list to access.
        index_str: The index to access as a string.

    Returns:
        The value at the specified index, or an error message if the index is invalid.
    """

    if not is_valid_integer(index_str):
        return "Error: Invalid index.  Please enter a valid integer."

    try:
        index = int(index_str)
    except ValueError:
        return "Error: Could not convert index to integer."

    if index < 0 or index >= len(data):
        return "Error: Index out of bounds."

    return data[index]


# --- Example Usage (Illustrative - Authentication needs to be integrated) ---

if __name__ == "__main__":
    # Example array
    my_array = [10, "hello", 3.14, 42, "world"]

    # Simulate user input (replace with actual input mechanism)
    user_index_input = input("Enter the index to retrieve: ")

    # Get the value from the array
    result = get_array_value(my_array, user_index_input)

    print(result)


# --- Additional Security Considerations (Beyond this code unit) ---

# 1. Rate Limiting:  Implement rate limiting on login attempts to prevent brute-force attacks.  This is typically done at the application level (e.g., using a framework like Flask or Django).

# 2. Secure Session Management: Use secure session management techniques (e.g., HTTPOnly cookies, secure flags) to protect user sessions.  Again, this is usually handled by the web framework.

# 3. Encryption at Rest:  If storing sensitive data (e.g., user profiles, API keys), encrypt the data at rest using a strong encryption algorithm (e.g., AES).

# 4. Least Privilege:  Grant users only the minimum necessary permissions to perform their tasks.

# 5. Regular Security Audits:  Conduct regular security audits to identify and address potential vulnerabilities.

# 6. Input Sanitization:  In addition to validation, sanitize user inputs to prevent cross-site scripting (XSS) and other injection attacks.  This involves escaping or removing potentially harmful characters.

# 7. Error Handling:  Avoid exposing sensitive information in error messages.  Log errors to a secure location for debugging purposes.

# 8. Dependency Management:  Keep all dependencies up to date to patch security vulnerabilities.  Use a dependency management tool (e.g., pip) to track and update dependencies.

# 9. Two-Factor Authentication (2FA):  Implement 2FA to add an extra layer of security to user accounts.

# 10. Password Reset: Implement a secure password reset mechanism that uses email verification or other methods to prevent unauthorized access.

# 11. First Login Mode:  The example code does not include a first login mode.  This would require a mechanism to detect if a user is logging in for the first time and force them to create a strong password.  This could involve checking a flag in the user's database record.

# 12. Credentials Protection: The example code does not store credentials.  If it did, it would need to encrypt them and restrict access to the encrypted data.

# 13. Transmission Security:  If transmitting authentication credentials, use HTTPS to encrypt the communication channel.

