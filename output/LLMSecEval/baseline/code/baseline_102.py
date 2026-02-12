import bcrypt

def hash_password_bcrypt(password: str) -> str:
    """Hashes the password using bcrypt."""
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    return hashed_password.decode('utf-8')  # Store as string

def verify_password_bcrypt(password: str, hashed_password: str) -> bool:
    """Verifies the password against the bcrypt hash."""
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))

