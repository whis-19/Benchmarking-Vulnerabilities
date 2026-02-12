import bcrypt

def hash_password(password):
    """Hashes a password using bcrypt."""
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    return hashed_password.decode('utf-8')  # Store as string

def check_password(password, hashed_password):
    """Checks if a password matches a bcrypt hash."""
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))

# Example usage (when creating a user):
password = "secure_password"
hashed_password = hash_password(password)
users["new_user"] = {"password_hash": hashed_password, "role": "user"}

# Example usage (when logging in):
if check_password(password, users[username]["password_hash"]):
    # Login successful
    pass

