import bcrypt
import os
from typing import Optional

def hash_password(password: str) -> bytes:
    """
    Hashes a password using bcrypt.

    Args:
        password: The password to hash.

    Returns:
        The bcrypt hash of the password as bytes.
    """
    # Generate a salt.  The rounds parameter controls the cost factor.
    # Higher rounds mean more security but also more computation time.
    # bcrypt.gensalt() uses a cryptographically secure random number generator.
    salt = bcrypt.gensalt(rounds=12)  # Adjust rounds as needed for performance/security tradeoff

    # Hash the password using the generated salt.  Encoding to bytes is crucial.
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed_password


def validate_password(hashed_password: bytes, typed_password: str) -> bool:
    """
    Compares a typed password against a bcrypt hashed password.

    Args:
        hashed_password: The bcrypt hash of the password (bytes).
        typed_password: The password entered by the user (string).

    Returns:
        True if the passwords match, False otherwise.
    """
    # bcrypt.checkpw handles the salt extraction and comparison.
    # Encoding the typed password to bytes is crucial.
    return bcrypt.checkpw(typed_password.encode('utf-8'), hashed_password)


def generate_temporary_password(length: int = 16) -> str:
    """
    Generates a cryptographically secure temporary password.

    Args:
        length: The desired length of the password.

    Returns:
        A randomly generated password.
    """
    # Use secrets module for cryptographically secure random number generation.
    import secrets
    import string
    alphabet = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(alphabet) for i in range(length))


# Example Usage (Illustrative - DO NOT HARDCODE PASSWORDS IN REAL APPLICATIONS)
if __name__ == '__main__':
    # 1. Hashing a new password (e.g., during user registration)
    new_password = "P@$$wOrd123"  # Replace with user-provided password
    hashed_pw = hash_password(new_password)
    print(f"Hashed password: {hashed_pw}")

    # Store the hashed_pw in your database (NOT the plaintext password!)

    # 2. Validating a password (e.g., during login)
    typed_password = "P@$$wOrd123"  # Replace with user-entered password
    is_valid = validate_password(hashed_pw, typed_password)
    print(f"Password validation: {is_valid}")

    # 3. Example of generating a temporary password
    temp_password = generate_temporary_password()
    print(f"Generated temporary password: {temp_password}")

    # Important Considerations:

    # - Key Management:  bcrypt handles the salt internally, so you don't need to manage it separately.  However, you *must* store the *hashed* password securely in your database.  Use appropriate database encryption and access controls.

    # - Rate Limiting: Implement rate limiting on login attempts to prevent brute-force attacks.  This is typically done at the application or web server level.

    # - Secure Session Management: Use secure session management techniques (e.g., HTTPOnly cookies, secure flags, session timeouts) to protect user sessions.

    # - Temporary Passwords:  When using temporary passwords, store them in memory (e.g., in a dictionary or cache) with an expiration time.  After the expiration time, the temporary password should be invalidated.  Consider using a dedicated library for managing temporary credentials.

    # - Outbound Authentication:  If your application needs to authenticate to other services, store the credentials (e.g., API keys, usernames/passwords) securely.  Encrypt them in your configuration files or use a secrets management service (e.g., HashiCorp Vault, AWS Secrets Manager).  Restrict access to these files/services using appropriate permissions.

    # - Automatic Password Updates:  Implement a mechanism to automatically update passwords or keys at specified time intervals.  This typically involves a system administrator who can trigger the update process.  The new passwords/keys should be generated using a cryptographically secure random number generator.

    # - Never Hardcode Credentials:  Never, ever hardcode passwords, API keys, or other sensitive information directly in your code.  Use environment variables, configuration files, or secrets management services.

    # - Database Security:  Ensure your database is properly secured with strong passwords, encryption, and access controls.

    # - Regular Security Audits:  Conduct regular security audits of your code and infrastructure to identify and address potential vulnerabilities.

