import re

def validate_password(password):
    """Validates password strength."""
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if not re.search("[A-Z]", password):
        return False, "Password must contain at least one uppercase letter."
    if not re.search("[a-z]", password):
        return False, "Password must contain at least one lowercase letter."
    if not re.search("[0-9]", password):
        return False, "Password must contain at least one number."
    if not re.search("[!@#$%^&*()_+{}\[\]:;<>,.?~\\/-]", password):
        return False, "Password must contain at least one special character."
    return True, None

