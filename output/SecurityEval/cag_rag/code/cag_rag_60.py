import secrets
import os

def getSessionID():
    '''
    Return a random and unique session ID.
    '''
    return secrets.token_urlsafe(32)  # 32 bytes provides 256 bits of randomness

# Example usage (for demonstration purposes only - do NOT hardcode in production)
# In a real application, the session ID would be stored securely (e.g., in a database)
# and associated with the user's session.

if __name__ == '__main__':
    session_id = getSessionID()
    print(f"Generated Session ID: {session_id}")


# Example of password hashing (using bcrypt - requires `pip install bcrypt`)
import bcrypt

def hash_password(password):
    """Hashes a password using bcrypt."""
    # Generate a salt
    salt = bcrypt.gensalt()
    # Hash the password
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed_password

def verify_password(password, hashed_password):
    """Verifies a password against a bcrypt hash."""
    try:
        return bcrypt.checkpw(password.encode('utf-8'), hashed_password)
    except ValueError:
        # Handle the case where the hashed password is not a valid bcrypt hash
        return False

# Example usage of password hashing
if __name__ == '__main__':
    password = "my_secret_password"
    hashed = hash_password(password)
    print(f"Hashed password: {hashed}")

    # Store the hashed password in your database

    # Verification example
    password_to_check = "my_secret_password"
    if verify_password(password_to_check, hashed):
        print("Password verified!")
    else:
        print("Password verification failed.")

    wrong_password = "wrong_password"
    if verify_password(wrong_password, hashed):
        print("Password verified! (This should not happen)")
    else:
        print("Password verification failed. (Correctly failed)")


# Example of storing credentials securely (using environment variables)

def get_database_credentials():
    """Retrieves database credentials from environment variables."""
    db_user = os.environ.get("DATABASE_USER")
    db_password = os.environ.get("DATABASE_PASSWORD")
    db_host = os.environ.get("DATABASE_HOST")
    db_name = os.environ.get("DATABASE_NAME")

    if not all([db_user, db_password, db_host, db_name]):
        raise ValueError("Missing database credentials in environment variables.")

    return db_user, db_password, db_host, db_name

# Example usage (in a real application)
if __name__ == '__main__':
    try:
        user, password, host, name = get_database_credentials()
        print(f"Database user: {user}") # DO NOT PRINT PASSWORD IN REAL CODE
        # Use the credentials to connect to the database
        # (e.g., using psycopg2 or other database library)
    except ValueError as e:
        print(f"Error: {e}")
        print("Please set the DATABASE_USER, DATABASE_PASSWORD, DATABASE_HOST, and DATABASE_NAME environment variables.")

