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
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            first_name TEXT NOT NULL,
            last_name TEXT NOT NULL,
            email TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()

create_table()  # Ensure the table exists on startup


def validate_input(username, password, first_name, last_name, email):
    """
    Validates user input.  Returns an error message if invalid, None otherwise.
    This is a basic example; expand as needed.
    """
    if not (4 <= len(username) <= 50):
        return "Username must be between 4 and 50 characters."
    if not (8 <= len(password) <= 100):  # Adjust password length requirements
        return "Password must be between 8 and 100 characters."
    if not (1 <= len(first_name) <= 50):
        return "First name must be between 1 and 50 characters."
    if not (1 <= len(last_name) <= 50):
        return "Last name must be between 1 and 50 characters."
    if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
        return "Invalid email address."
    return None  # No errors


def register_user(username, password, first_name, last_name, email) -> str:
    """
    Registers a new user.

    Args:
        username: The username.
        password: The password.
        first_name: The first name.
        last_name: The last name.
        email: The email address.

    Returns:
        A message indicating success or failure.
    """

    error_message = validate_input(username, password, first_name, last_name, email)
    if error_message:
        return error_message

    try:
        # Hash the password
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(BCRYPT_ROUNDS))

        # Connect to the database
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()

        # Check if the username already exists using a parameterized query
        cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
        existing_user = cursor.fetchone()

        if existing_user:
            conn.close()
            return "Username already exists."

        # Insert the new user into the database using a parameterized query
        cursor.execute(
            "INSERT INTO users (username, password_hash, first_name, last_name, email) VALUES (?, ?, ?, ?, ?)",
            (username, hashed_password.decode('utf-8'), first_name, last_name, email),
        )
        conn.commit()
        conn.close()

        return "Registration succeeded."

    except sqlite3.Error as e:
        print(f"Database error: {e}")  # Log the error, don't expose directly to user
        return "Registration failed due to a database error."  # Generic error message


def authenticate_user(username, password) -> Optional[str]:
    """
    Authenticates a user.

    Args:
        username: The username.
        password: The password.

    Returns:
        The username if authentication is successful, None otherwise.
    """
    try:
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()

        # Retrieve the user's data from the database using a parameterized query
        cursor.execute("SELECT username, password_hash FROM users WHERE username = ?", (username,))
        user_data = cursor.fetchone()
        conn.close()

        if user_data:
            username_from_db, password_hash_from_db = user_data
            # Verify the password hash
            if bcrypt.checkpw(password.encode('utf-8'), password_hash_from_db.encode('utf-8')):
                return username_from_db  # Authentication successful
            else:
                return None  # Incorrect password
        else:
            return None  # User not found

    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return None  # Authentication failed due to a database error


if __name__ == '__main__':
    # Example usage
    username = "testuser"
    password = "securePassword123"
    first_name = "John"
    last_name = "Doe"
    email = "john.doe@example.com"

    registration_result = register_user(username, password, first_name, last_name, email)
    print(f"Registration: {registration_result}")

    if registration_result == "Registration succeeded.":
        # Simulate login
        authenticated_user = authenticate_user(username, password)
        if authenticated_user:
            print(f"Authentication successful for user: {authenticated_user}")
        else:
            print("Authentication failed.")

        # Simulate login with incorrect password
        authenticated_user = authenticate_user(username, "wrongpassword")
        if authenticated_user:
            print(f"Authentication successful for user: {authenticated_user}")
        else:
            print("Authentication failed with wrong password.")

