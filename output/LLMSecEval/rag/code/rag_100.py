import sqlite3
import hashlib
import os
import secrets
import configparser

# --- Configuration Loading ---
config = configparser.ConfigParser()
config.read('config.ini')  # Store database path and other sensitive info in config.ini

DATABASE_PATH = config.get('Database', 'path', fallback='users.db')  # Default to users.db if not in config

def create_user(username, password):
    """
    Creates a new user account in the database.

    Args:
        username (str): The username for the new account.
        password (str): The user's password.
    """

    # --- Input Validation (Basic) ---
    if not username or not password:
        raise ValueError("Username and password cannot be empty.")

    # --- Generate Salt ---
    salt = secrets.token_hex(16)  # 16 bytes = 32 hex characters

    # --- Hash Password ---
    hashed_password = hash_password(password, salt)

    # --- Database Insertion ---
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()

        # --- Use parameterized query to prevent SQL injection ---
        cursor.execute("INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)",
                       (username, hashed_password, salt))
        conn.commit()
        print(f"User '{username}' created successfully.")

    except sqlite3.Error as e:
        print(f"Database error: {e}")
        raise  # Re-raise the exception to be handled upstream if needed

    finally:
        if conn:
            conn.close()


def hash_password(password, salt):
    """
    Hashes the password using SHA-256 with the provided salt.

    Args:
        password (str): The password to hash.
        salt (str): The salt to use.

    Returns:
        str: The hexadecimal representation of the hashed password.
    """
    salted_password = salt + password
    hashed_password = hashlib.sha256(salted_password.encode('utf-8')).hexdigest()
    return hashed_password


def verify_password(username, password):
    """
    Verifies the provided password against the stored hash for the given username.

    Args:
        username (str): The username to verify.
        password (str): The password to verify.

    Returns:
        bool: True if the password is correct, False otherwise.
    """
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()

        # --- Use parameterized query to prevent SQL injection ---
        cursor.execute("SELECT password_hash, salt FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()

        if result:
            stored_hash, salt = result
            hashed_password = hash_password(password, salt)
            return hashed_password == stored_hash
        else:
            return False  # User not found

    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return False  # Handle database errors gracefully

    finally:
        if conn:
            conn.close()


def initialize_database():
    """
    Creates the 'users' table if it doesn't exist.  This should be called once
    when the application is first set up.
    """
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL
            )
        """)
        conn.commit()
        print("Database initialized/checked successfully.")

    except sqlite3.Error as e:
        print(f"Database error during initialization: {e}")
        raise  # Re-raise for handling at a higher level

    finally:
        if conn:
            conn.close()


# --- Example Usage (Illustrative) ---
if __name__ == '__main__':
    initialize_database()  # Ensure the database is set up

    # --- Example: Create a user ---
    try:
        create_user("testuser", "P@$$wOrd123")  # Replace with user input
    except ValueError as e:
        print(f"Error creating user: {e}")
    except sqlite3.IntegrityError:
        print("Username already exists.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")


    # --- Example: Verify a password ---
    if verify_password("testuser", "P@$$wOrd123"):
        print("Password verified successfully.")
    else:
        print("Password verification failed.")

    if verify_password("testuser", "wrongpassword"):
        print("Password verified successfully.")
    else:
        print("Password verification failed.")


# --- config.ini example ---
# [Database]
# path = /path/to/your/secure/users.db  # Absolute path is recommended

