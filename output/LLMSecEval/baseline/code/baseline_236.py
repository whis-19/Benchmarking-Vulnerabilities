import sqlite3
import hashlib
import secrets
import os

# Database setup (consider using a more robust database like PostgreSQL for production)
DATABASE_FILE = 'users.db'

def create_table():
    """Creates the users table if it doesn't exist."""
    conn = None  # Initialize conn to None
    try:
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                first_name TEXT,
                last_name TEXT,
                email TEXT
            )
        ''')
        conn.commit()
    except sqlite3.Error as e:
        print(f"Database error: {e}")
    finally:
        if conn:
            conn.close()


create_table()  # Ensure the table exists when the script runs


def generate_salt():
    """Generates a random salt for password hashing."""
    return secrets.token_hex(16)  # 16 bytes = 32 hex characters


def hash_password(password, salt):
    """Hashes the password using SHA-256 with a salt."""
    salted_password = salt + password
    hashed_password = hashlib.sha256(salted_password.encode('utf-8')).hexdigest()
    return hashed_password


def register_user(username, password, first_name, last_name, email):
    """Registers a new user in the database."""
    conn = None  # Initialize conn to None
    try:
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()

        # Check if username already exists
        cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
        if cursor.fetchone():
            return "Username already exists."

        # Generate salt and hash password
        salt = generate_salt()
        password_hash = hash_password(password, salt)

        # Insert user data into the database
        cursor.execute('''
            INSERT INTO users (username, password_hash, salt, first_name, last_name, email)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (username, password_hash, salt, first_name, last_name, email))

        conn.commit()
        return "Registration successful!"

    except sqlite3.IntegrityError:
        return "Username already exists."  # Handle potential race conditions
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return f"Registration failed: {e}"  # Return the error message for debugging
    finally:
        if conn:
            conn.close()


# Example usage (replace with your web framework's input handling)
if __name__ == '__main__':
    # Simulate form data
    username = input("Enter username: ")
    password = input("Enter password: ")
    first_name = input("Enter first name: ")
    last_name = input("Enter last name: ")
    email = input("Enter email: ")

    # Register the user
    registration_result = register_user(username, password, first_name, last_name, email)
    print(registration_result)


#  Important Security Considerations and Improvements:

# 1.  Input Validation and Sanitization:
#     - **Crucially important:**  The provided code *lacks* input validation and sanitization.  This is a major security vulnerability.  You *must* validate and sanitize all user inputs to prevent SQL injection, cross-site scripting (XSS), and other attacks.  Use appropriate validation techniques for each field (e.g., email validation, length restrictions, character whitelisting).  Sanitize data before inserting it into the database.  Libraries like `bleach` can help with XSS prevention.  Parameterization (as used in the `execute` calls) prevents SQL injection for the data itself, but you still need to validate the *structure* of the input.

# 2.  Password Hashing:
#     - **Use a strong password hashing library:**  While SHA-256 with a salt is better than storing passwords in plain text, it's not the recommended approach.  Use a dedicated password hashing library like `bcrypt`, `scrypt`, or `argon2`.  These libraries are designed to be computationally expensive, making password cracking much harder.  They also handle salt generation and storage securely.  `bcrypt` is a good starting point.

#

