import re
import sqlite3
import hashlib
import os

# --- Database Configuration ---
DATABASE_FILE = "users.db"  # Consider using environment variables for sensitive info
# --- Email Validation ---
EMAIL_REGEX = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"

def create_database():
    """Creates the database and tables if they don't exist."""
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()

    # Create users table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL
        )
    """)

    # Create a separate table for user-specific data (example)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS user_data (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            data TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    """)

    conn.commit()
    conn.close()

def validate_email(email):
    """Validates the email address using a regular expression."""
    if not re.match(EMAIL_REGEX, email):
        return False
    return True

def hash_password(password, salt=None):
    """Hashes the password using SHA-256 with a salt."""
    if salt is None:
        salt = os.urandom(16).hex()  # Generate a random salt
    salted_password = salt + password
    hashed_password = hashlib.sha256(salted_password.encode('utf-8')).hexdigest()
    return hashed_password, salt

def create_user(email, password):
    """Creates a new user in the database."""
    if not validate_email(email):
        return "Invalid email address."

    hashed_password, salt = hash_password(password)

    try:
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()
        cursor.execute("INSERT INTO users (email, password_hash, salt) VALUES (?, ?, ?)", (email, hashed_password, salt))
        conn.commit()
        conn.close()
        return "User created successfully."
    except sqlite3.IntegrityError:
        return "Email address already exists."
    except Exception as e:
        return f"An error occurred: {e}"

def verify_password(email, password):
    """Verifies the password against the stored hash."""
    try:
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()
        cursor.execute("SELECT password_hash, salt FROM users WHERE email = ?", (email,))
        result = cursor.fetchone()
        conn.close()

        if result:
            stored_hash, salt = result
            hashed_password, _ = hash_password(password, salt)  # Use the stored salt
            return hashed_password == stored_hash
        else:
            return False  # User not found
    except Exception as e:
        print(f"Error during password verification: {e}") # Log the error
        return False

def unsubscribe(email):
    """Unsubscribes the user from the database."""
    if not validate_email(email):
        return "Invalid email address."

    try:
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()

        # Use parameterized query to prevent SQL injection
        cursor.execute("DELETE FROM users WHERE email = ?", (email,))
        rows_deleted = cursor.rowcount  # Get the number of rows deleted
        conn.commit()
        conn.close()

        if rows_deleted > 0:
            return "You have been successfully unsubscribed."
        else:
            return "Email address not found in our database."

    except Exception as e:
        print(f"Error during unsubscription: {e}") # Log the error
        return f"An error occurred: {e}"

# Example Usage (for testing - remove in production)
if __name__ == '__main__':
    create_database()  # Ensure the database exists

    # Example: Create a user
    result = create_user("test@example.com", "P@$$wOrd")
    print(result)

    # Example: Verify password
    is_valid = verify_password("test@example.com", "P@$$wOrd")
    print(f"Password verification: {is_valid}")

    # Example: Unsubscribe a user
    result = unsubscribe("test@example.com")
    print(result)

    result = unsubscribe("nonexistent@example.com")
    print(result)

