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
                first_name TEXT NOT NULL,
                last_name TEXT NOT NULL,
                email TEXT NOT NULL
            )
        """)
        conn.commit()
    except sqlite3.Error as e:
        print(f"Database error: {e}")
    finally:
        if conn:
            conn.close()


def register_user(username, password, first_name, last_name, email):
    """Registers a new user, hashing the password and storing it in the database."""

    # Input validation
    if not is_valid_username(username):
        return "Invalid username format."
    if not is_valid_password(password):
        return "Invalid password format."
    if not is_valid_name(first_name):
        return "Invalid first name format."
    if not is_valid_name(last_name):
        return "Invalid last name format."
    if not is_valid_email(email):
        return "Invalid email format."

    try:
        hashed_password = hash_password(password)
    except Exception as e:
        print(f"Error hashing password: {e}")
        return "Error processing password."

    conn = None  # Initialize conn to None
    try:
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()

        # Check if username already exists using parameterized query
        cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
        if cursor.fetchone():
            return "Username already exists."

        # Insert user data using parameterized query
        cursor.execute("""
            INSERT INTO users (username, password_hash, first_name, last_name, email)
            VALUES (?, ?, ?, ?, ?)
        """, (username, hashed_password, first_name, last_name, email))
        conn.commit()
        return "Registration successful."

    except sqlite3.IntegrityError:
        return "Username already exists."  # Handle potential race condition
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return "Registration failed due to a database error."
    finally:
        if conn:
            conn.close()


def hash_password(password):
    """Hashes the password using bcrypt."""
    password_bytes = password.encode('utf-8')
    hashed = bcrypt.hashpw(password_bytes, bcrypt.gensalt(BCRYPT_ROUNDS))
    return hashed.decode('utf-8')  # Store as string


def verify_password(password, hashed_password):
    """Verifies the password against the stored hash."""
    password_bytes = password.encode('utf-8')
    hashed_password_bytes = hashed_password.encode('utf-8')
    return bcrypt.checkpw(password_bytes, hashed_password_bytes)


def is_valid_username(username):
    """Validates the username format (alphanumeric, 3-20 characters)."""
    return bool(re.match(r"^[a-zA-Z0-9]{3,20}$", username))


def is_valid_password(password):
    """Validates the password format (at least 8 characters, one uppercase, one lowercase, one digit)."""
    return bool(re.match(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,}$", password))


def is_valid_name(name):
    """Validates the name format (alphabetic, 2-50 characters)."""
    return bool(re.match(r"^[a-zA-Z]{2,50}$", name))


def is_valid_email(email):
    """Validates the email format."""
    return bool(re.match(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", email))


def get_user(username):
    """Retrieves a user from the database by username."""
    conn = None
    try:
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()
        cursor.execute("SELECT id, username, password_hash, first_name, last_name, email FROM users WHERE username = ?", (username,))
        row = cursor.fetchone()
        if row:
            return {
                "id": row[0],
                "username": row[1],
                "password_hash": row[2],
                "first_name": row[3],
                "last_name": row[4],
                "email": row[5]
            }
        else:
            return None
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return None
    finally:
        if conn:
            conn.close()


# Example usage (replace with your web framework's request handling)
if __name__ == '__main__':
    create_table()  # Ensure the table exists

    # Example registration
    registration_result = register_user(
        "testuser",
        "P@sswOrd123",
        "John",
        "Doe",
        "john.doe@example.com"
    )
    print(f"Registration result: {registration_result}")

    # Example login verification
    user = get_user("testuser")
    if user:
        password_to_check = "P@sswOrd123"
        if verify_password(password_to_check, user["password_hash"]):
            print("Login successful!")
        else:
            print("Login failed: Incorrect password.")
    else:
        print("Login failed: User not found.")

    # Example of invalid input
    registration_result = register_user(
        "invalid-username!",
        "weak",
        "123",
        "456",
        "invalid-email"
    )
    print(f"Registration result (invalid input): {registration_result}")

