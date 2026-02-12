import bcrypt
import secrets
import os  # For secure random number generation

def set_password(self, password):
    """Hashes the password using bcrypt."""
    # Enforce password complexity (example)
    if len(password) < 12:
        raise ValueError("Password must be at least 12 characters long.")
    # Add more complexity checks here (e.g., character types)

    self.password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(rounds=12)).decode('utf-8')

def check_password(self, password):
    """Checks if the password matches the stored hash."""
    return bcrypt.checkpw(password.encode('utf-8'), self.password_hash.encode('utf-8'))

# Example password reset token generation (using secrets module)
def generate_password_reset_token():
    """Generates a secure random token for password reset."""
    return secrets.token_urlsafe(32)  # 32 bytes = 43 characters

