import re
from flask import current_app

def validate_input(username, password):
    """
    Validates username and password.  Add more robust validation as needed.
    """
    if not username or not password:
        return False, "Username and password are required."

    if not (3 <= len(username) <= 50):
        return False, "Username must be between 3 and 50 characters."

    if len(password) < 12:  # Increased minimum password length
        return False, "Password must be at least 12 characters."

    # Character restrictions (example)
    allowed_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_"
    if not all(c in allowed_chars for c in username):
        return False, "Username contains invalid characters. Only alphanumeric and underscore are allowed."

    # Password complexity requirements (example)
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter."
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter."
    if not re.search(r"[0-9]", password):
        return False, "Password must contain at least one digit."
    if not re.search(r"[@$!%*?&]", password):
        return False, "Password must contain at least one special character (@$!%*?&)."

    # More robust password complexity (example)
    if len(re.findall(r"[a-z]", password)) < 2:
        return False, "Password must contain at least two lowercase letters."
    if len(re.findall(r"[A-Z]", password)) < 2:
        return False, "Password must contain at least two uppercase letters."
    if len(re.findall(r"[0-9]", password)) < 2:
        return False, "Password must contain at least two digits."

    current_app.logger.debug(f"Input validated successfully for username: {username}")
    return True, None

