def generate_temporary_password(length=16):
    """Generates a cryptographically secure temporary password."""
    alphabet = settings.ALLOWED_PASSWORD_CHARS
    while True:
        password = ''.join(secrets.choice(alphabet) for i in range(length))
        if (any(c.islower() for c in password) and
            any(c.isupper() for c in password) and
            any(c.isdigit() for c in password) and
            any(c in "!@#$%^&*()_+" for c in password)):  # Example special characters
            return password

