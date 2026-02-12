import os
import re
from typing import Optional
import bcrypt  # Import bcrypt for stronger password hashing
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Ideally, these should be stored in a secure configuration file or a secrets management service.
# NEVER hardcode credentials directly in the code.
ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME")
if ADMIN_USERNAME is None:
    raise EnvironmentError("ADMIN_USERNAME environment variable not set.")

ADMIN_PASSWORD_HASH = os.environ.get("ADMIN_PASSWORD_HASH")
if ADMIN_PASSWORD_HASH is None:
    raise EnvironmentError("ADMIN_PASSWORD_HASH environment variable not set.")

HAS_ADMIN_ACCESS = False


def verify_password(password: str, hashed_password: str) -> bool:
    """Verifies a password against a stored hash using bcrypt.

    Args:
        password: The password to verify.
        hashed_password: The stored hash of the password.

    Returns:
        True if the password matches the hash, False otherwise.
    """
    try:
        # Timing attack consideration: bcrypt.checkpw is generally resistant, but be aware.
        return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))
    except ValueError:
        # Handle the case where the hashed_password is not a valid bcrypt hash
        logging.error("Invalid bcrypt hash format.")  # Log securely
        return False
    except Exception as e:
        logging.exception("An unexpected error occurred during password verification: %s", e)
        return False


def admin_access(request) -> bool:
    """
    Validates the username and password from the request for admin access.
    Flags that the user has admin access if authentication is successful.

    Args:
        request:  A dictionary-like object representing the HTTP request.
                  It should contain 'username' and 'password' keys.

    Returns:
        True if admin access is granted, False otherwise.
    """
    global HAS_ADMIN_ACCESS  # Use global keyword to modify the global variable

    username = request.get("username")
    password = request.get("password")

    if not username or not password:
        logging.warning("Username or password missing from request.")  # Log this securely
        return False

    # Input validation:  Example of a more robust allowlist using regular expressions.
    if not isinstance(username, str) or not re.match(r"^[a-zA-Z0-9_-]{3,20}$", username):
        logging.warning("Invalid username format.  Must be 3-20 alphanumeric characters, underscores, or hyphens.")
        return False

    if not isinstance(password, str) or len(password) > 100:  # Limit password length
        logging.warning("Invalid password format.  Password too long.")
        return False

    if username == ADMIN_USERNAME and verify_password(password, ADMIN_PASSWORD_HASH):
        HAS_ADMIN_ACCESS = True
        logging.info("Admin access granted for user: %s", username)  # Log this securely
        return True
    else:
        logging.warning("Invalid username or password for user: %s", username)  # Log this securely
        return False


def generate_password_hash(password: str, complexity_config: Optional[dict] = None) -> str:
    """Generates a secure hash of a password using bcrypt.

    Args:
        password: The password to hash.
        complexity_config: A dictionary containing password complexity requirements.
                           If None, default requirements are used.  Example:
                           {
                               "min_length": 8,
                               "require_digit": True,
                               "require_uppercase": True,
                               "require_lowercase": True,
                               "require_special": True
                           }

    Returns:
        The bcrypt hash of the password as a string.
    """

    if complexity_config is None:
        complexity_config = {
            "min_length": 8,
            "require_digit": True,
            "require_uppercase": True,
            "require_lowercase": True,
            "require_special": True
        }

    # Validate password complexity based on configuration
    if len(password) < complexity_config.get("min_length", 8):
        raise ValueError(f"Password must be at least {complexity_config.get('min_length', 8)} characters long.")
    if complexity_config.get("require_digit", True) and not any(char.isdigit() for char in password):
        raise ValueError("Password must contain at least one digit.")
    if complexity_config.get("require_uppercase", True) and not any(char.isupper() for char in password):
        raise ValueError("Password must contain at least one uppercase letter.")
    if complexity_config.get("require_lowercase", True) and not any(char.islower() for char in password):
        raise ValueError("Password must contain at least one lowercase letter.")
    if complexity_config.get("require_special", True) and not any(not char.isalnum() for char in password):
        raise ValueError("Password must contain at least one special character.")

    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    return hashed_password


# Example usage (for initial setup - NEVER store the plain password):
if __name__ == '__main__':
    # This part is ONLY for initial setup and should be removed from production code.
    # It demonstrates how to generate a password hash.

    # Example of configuring password complexity
    password_config = {
        "min_length": 12,
        "require_digit": True,
        "require_uppercase": True,
        "require_lowercase": True,
        "require_special": True
    }

    initial_admin_password = "StrongAdminPassword123!"  # Replace with a strong password
    try:
        hashed_password = generate_password_hash(initial_admin_password, password_config)
        print(f"Hashed password for initial admin setup: {hashed_password}")
        # Store this hashed_password securely (e.g., in a database or configuration file or secrets management service).
        # Then, replace the ADMIN_PASSWORD_HASH value at the top of the file with this hash.
        # In a real application, you would set the ADMIN_PASSWORD_HASH environment variable here.
        os.environ["ADMIN_PASSWORD_HASH"] = hashed_password  # Simulate setting the environment variable
        ADMIN_PASSWORD_HASH = hashed_password # Update the global variable for testing

        # Example request (for testing):
        request_data = {"username": "admin", "password": "StrongAdminPassword123!"}  # Use the initial password for testing
        if admin_access(request_data):
            print("Admin access granted (test).")
        else:
            print("Admin access denied (test).")

        print(f"HAS_ADMIN_ACCESS: {HAS_ADMIN_ACCESS}")

    except ValueError as e:
        print(f"Error generating password hash: {e}")

    # Reminders for production:
    print("\n*** IMPORTANT SECURITY REMINDERS FOR PRODUCTION ***")
    print("- Ensure all communication is over HTTPS.")
    print("- Implement rate limiting and account lockout to prevent brute-force attacks.")
    print("- Consider using a secrets management service (e.g., HashiCorp Vault, AWS Secrets Manager) for storing sensitive information.")
    print("- Implement two-factor authentication (2FA) for admin accounts.")
    print("- Remove this example usage section from production code.")

