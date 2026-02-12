import bcrypt
import sqlite3
import secrets
import os

# Database configuration (consider using environment variables for sensitive data)
DATABASE_FILE = "user_database.db"

def create_user(username, password):
    """
    Creates a new user account in the database.

    Args:
        username (str): The username for the new account.
        password (str): The password for the new account.

    Returns:
        bool: True if the user was created successfully, False otherwise.
    """

    # Input validation (example - add more as needed)
    if not (isinstance(username, str) and isinstance(password, str)):
        print("Error: Invalid input types.")
        return False

    if not (4 <= len(username) <= 50 and 8 <= len(password) <= 100):  # Example length constraints
        print("Error: Username and password must be within specified length limits.")
        return False

    try:
        # Hash the password using bcrypt
        hashed_password = hash_password(password)

        # Connect to the database
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()

        # Use parameterized query to prevent SQL injection
        cursor.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, hashed_password))
        conn.commit()

        print(f"User '{username}' created successfully.")
        return True

    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return False
    finally:
        if conn:
            conn.close()


def hash_password(password):
    """
    Hashes a password using bcrypt.

    Args:
        password (str): The password to hash.

    Returns:
        str: The bcrypt hash of the password.
    """
    # Generate a salt
    salt = bcrypt.gensalt()

    # Hash the password with the salt
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)

    return hashed_password.decode('utf-8')  # Store as string in the database


def verify_password(password, hashed_password):
    """
    Verifies a password against a bcrypt hash.

    Args:
        password (str): The password to verify.
        hashed_password (str): The bcrypt hash to compare against.

    Returns:
        bool: True if the password matches the hash, False otherwise.
    """
    try:
        return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))
    except ValueError:
        # Handle cases where the hash is invalid (e.g., not a bcrypt hash)
        print("Error: Invalid password hash format.")
        return False


def initialize_database():
    """
    Initializes the database by creating the 'users' table if it doesn't exist.
    """
    conn = None  # Initialize conn to None
    try:
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()

        # Create the users table if it doesn't exist
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL
            )
        """)
        conn.commit()
        print("Database initialized successfully.")

    except sqlite3.Error as e:
        print(f"Database error during initialization: {e}")
    finally:
        if conn:
            conn.close()


def get_user(username):
    """
    Retrieves a user from the database by username.

    Args:
        username (str): The username to search for.

    Returns:
        tuple: A tuple containing the user's ID and password hash, or None if the user is not found.
    """
    conn = None
    try:
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()

        cursor.execute("SELECT id, password_hash FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()

        if user:
            return user  # Returns (id, password_hash)
        else:
            return None

    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return None
    finally:
        if conn:
            conn.close()


# Example usage:
if __name__ == "__main__":
    initialize_database()

    # Example: Create a new user
    username = input("Enter username: ")
    password = input("Enter password: ")
    if create_user(username, password):
        print("User created successfully.")
    else:
        print("User creation failed.")

    # Example: Verify a password
    retrieved_user = get_user(username)
    if retrieved_user:
        user_id, stored_hash = retrieved_user
        password_to_verify = input("Enter password to verify: ")
        if verify_password(password_to_verify, stored_hash):
            print("Password verified successfully.")
        else:
            print("Password verification failed.")
    else:
        print("User not found.")

