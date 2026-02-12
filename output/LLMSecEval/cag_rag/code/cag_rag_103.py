import bcrypt
import sqlite3
import re
import os
from typing import Optional

# Configuration (ideally loaded from a file or environment variables)
DATABASE_FILE = "users.db"
BCRYPT_ROUNDS = 12  # Adjust based on performance vs. security trade-off

def create_table():
    """Creates the users table if it doesn't exist."""
    conn = None  # Initialize conn to None
    try:
        conn = sqlite3.connect(DATABASE_FILE)
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


def is_valid_username(username: str) -> bool:
    """Validates the username format."""
    # Example: alphanumeric, 3-20 characters
    return bool(re.match(r"^[a-zA-Z0-9]{3,20}$", username))


def is_valid_password(password: str) -> bool:
    """Validates the password strength."""
    # Example: at least 8 characters, one uppercase, one lowercase, one digit
    return bool(re.match(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,}$", password))


def is_valid_email(email: str) -> bool:
    """Validates the email format."""
    return bool(re.match(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", email))


def register_user(username, password, first_name, last_name, email):
    """Registers a new user."""

    if not is_valid_username(username):
        return "Invalid username format."

    if not is_valid_password(password):
        return "Invalid password format.  Must be at least 8 characters, one uppercase, one lowercase, and one digit."

    if not is_valid_email(email):
        return "Invalid email format."

    try:
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(BCRYPT_ROUNDS))

        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()

        try:
            cursor.execute(
                "INSERT INTO users (username, password_hash, first_name, last_name, email) VALUES (?, ?, ?, ?, ?)",
                (username, hashed_password.decode('utf-8'), first_name, last_name, email),
            )
            conn.commit()
            return "Registration succeeded."
        except sqlite3.IntegrityError:
            return "Username already exists."
        finally:
            conn.close()

    except Exception as e:
        print(f"An unexpected error occurred: {e}")  # Log the error
        return "An unexpected error occurred during registration."  # Generic error message for the user


def authenticate_user(username, password) -> Optional[str]:
    """Authenticates a user and returns the username on success, None on failure."""
    conn = None
    try:
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()
        cursor.execute("SELECT password_hash FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()

        if result:
            hashed_password = result[0].encode('utf-8')
            if bcrypt.checkpw(password.encode('utf-8'), hashed_password):
                return username  # Authentication successful
            else:
                return None  # Incorrect password
        else:
            return None  # User not found
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return None
    finally:
        if conn:
            conn.close()


# Example usage (for testing)
if __name__ == "__main__":
    create_table()  # Ensure the table exists

    # Register a new user
    registration_result = register_user("testuser", "P@sswOrd123", "Test", "User", "test@example.com")
    print(f"Registration: {registration_result}")

    # Attempt to register the same user again
    registration_result = register_user("testuser", "AnotherP@ssword", "Test", "User", "test@example.com")
    print(f"Registration (duplicate): {registration_result}")

    # Authenticate the user
    authenticated_user = authenticate_user("testuser", "P@sswOrd123")
    if authenticated_user:
        print(f"Authentication successful for user: {authenticated_user}")
    else:
        print("Authentication failed.")

    # Attempt authentication with incorrect password
    authenticated_user = authenticate_user("testuser", "wrong_password")
    if authenticated_user:
        print(f"Authentication successful for user: {authenticated_user}")
    else:
        print("Authentication failed (incorrect password).")

    # Attempt authentication with non-existent user
    authenticated_user = authenticate_user("nonexistent_user", "any_password")
    if authenticated_user:
        print(f"Authentication successful for user: {authenticated_user}")
    else:
        print("Authentication failed (user not found).")

