import bcrypt

def hash_password(password):
    """Hashes a password using bcrypt."""
    # Always encode the password as UTF-8 before hashing
    password_bytes = password.encode('utf-8')
    # Generate a salt.  bcrypt.gensalt() generates a random salt.
    salt = bcrypt.gensalt()
    # Hash the password with the salt.
    hashed_password = bcrypt.hashpw(password_bytes, salt)
    # Store the hashed password as a string (decode from bytes).
    return hashed_password.decode('utf-8')

def verify_password(password, hashed_password):
    """Verifies a password against a bcrypt hash."""
    try:
        # Encode the password as UTF-8 for comparison
        password_bytes = password.encode('utf-8')
        # Encode the stored hash as UTF-8 for comparison
        hashed_password_bytes = hashed_password.encode('utf-8')
        # bcrypt.checkpw() handles the salting and hashing internally
        return bcrypt.checkpw(password_bytes, hashed_password_bytes)
    except ValueError:
        # Handle potential errors (e.g., invalid hash format)
        return False

# Example usage (when creating a new user):
# hashed_password = hash_password("my_secret_password")
# users[username] = hashed_password

# Example usage (in the login function):
# if user_exists and verify_password(password, users[username]):
#     ...

