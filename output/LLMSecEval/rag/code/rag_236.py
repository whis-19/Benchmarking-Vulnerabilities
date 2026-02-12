import sqlite3
import hashlib
import os
from configparser import ConfigParser

# Configuration
config = ConfigParser()
config.read('config.ini')  # Store database path and other sensitive info in config.ini

DATABASE_PATH = config.get('database', 'path', fallback='users.db')  # Default to users.db if not in config
DATABASE_USER = config.get('database', 'user', fallback=None)
DATABASE_PASSWORD = config.get('database', 'password', fallback=None)
DATABASE_HOST = config.get('database', 'host', fallback=None)
DATABASE_PORT = config.get('database', 'port', fallback=None)


def create_table():
    """Creates the users table if it doesn't exist."""
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                first_name TEXT,
                last_name TEXT,
                email TEXT
            )
        """)
        conn.commit()
    except sqlite3.Error as e:
        print(f"Database error: {e}")
    finally:
        if conn:
            conn.close()


def hash_password(password):
    """Hashes the password using SHA-256."""
    if not password:
        raise ValueError("Password cannot be empty.")  # Prevent empty passwords
    hashed_password = hashlib.sha256(password.encode('utf-8')).hexdigest()
    return hashed_password


def register_user(username, password, first_name, last_name, email):
    """Registers a new user."""

    # Input validation
    if not all([username, password, first_name, last_name, email]):
        return "All fields are required."

    if len(username) < 4:
        return "Username must be at least 4 characters long."

    if len(password) < 8:
        return "Password must be at least 8 characters long."

    if '@' not in email or '.' not in email:
        return "Invalid email format."

    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()

        # Check if username already exists using parameterized query
        cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
        if cursor.fetchone():
            return "Username already exists."

        # Hash the password
        password_hash = hash_password(password)

        # Insert user data using parameterized query
        cursor.execute("""
            INSERT INTO users (username, password_hash, first_name, last_name, email)
            VALUES (?, ?, ?, ?, ?)
        """, (username, password_hash, first_name, last_name, email))

        conn.commit()
        return "Registration successful."

    except sqlite3.IntegrityError:  # Handle potential unique constraint violation
        return "Username already exists."
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return "Registration failed due to a database error."
    finally:
        if conn:
            conn.close()


def verify_password(username, password):
    """Verifies the password against the stored hash."""
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()

        # Retrieve the password hash for the given username
        cursor.execute("SELECT password_hash FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()

        if result:
            stored_hash = result[0]
            hashed_password = hash_password(password)
            return hashed_password == stored_hash
        else:
            return False  # User not found

    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return False
    finally:
        if conn:
            conn.close()


# Example Usage (for testing - REMOVE in production)
if __name__ == '__main__':
    # Create the table if it doesn't exist
    create_table()

    # Example registration
    registration_result = register_user("testuser", "P@$$wOrd123", "Test", "User", "test@example.com")
    print(registration_result)

    # Example login verification
    if verify_password("testuser", "P@$$wOrd123"):
        print("Login successful!")
    else:
        print("Login failed.")

    if verify_password("testuser", "wrongpassword"):
        print("Login successful!")
    else:
        print("Login failed.")

    # Example of trying to register the same user again
    registration_result = register_user("testuser", "AnotherPassword", "Test", "User", "test@example.com")
    print(registration_result)

