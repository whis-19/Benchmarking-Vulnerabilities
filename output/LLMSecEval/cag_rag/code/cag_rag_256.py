import bcrypt

def hash_password(password: str) -> str:
    """Hashes a password using bcrypt."""
    if not isinstance(password, str):
        raise TypeError("Password must be a string.")

    # Generate a salt and hash the password
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    return hashed_password.decode('utf-8')  # Store as a string

def verify_password(password: str, hashed_password: str) -> bool:
    """Verifies a password against its hash using bcrypt."""
    if not isinstance(password, str):
        raise TypeError("Password must be a string.")
    if not isinstance(hashed_password, str):
        raise TypeError("Hashed password must be a string.")

    try:
        return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))
    except ValueError:
        # Handle the case where the hashed password is not a valid bcrypt hash
        return False

# Example usage:
if __name__ == '__main__':
    password = "mysecretpassword"
    hashed = hash_password(password)
    print(f"Hashed password: {hashed}")

    is_valid = verify_password(password, hashed)
    print(f"Password is valid: {is_valid}")

    is_valid = verify_password("wrongpassword", hashed)
    print(f"Password is valid: {is_valid}")

