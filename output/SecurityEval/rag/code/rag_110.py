import hashlib
import os
import secrets
import sqlite3  # Assuming SQLite for database interaction, adjust as needed

# Configuration (ideally loaded from a separate, secure file)
DATABASE_PATH = "user_data.db"  # Store in a secure location outside the web root
CONFIG_FILE = "config.ini" # Example config file name

def generate_salt():
    """Generates a random salt for password hashing."""
    return secrets.token_hex(16)  # 16 bytes = 32 hex characters


def hash_password(password, salt):
    """Hashes the password using SHA-256 with a salt."""
    salted_password = salt.encode('utf-8') + password.encode('utf-8')
    hashed_password = hashlib.sha256(salted_password).hexdigest()
    return hashed_password


def create_user_table():
    """Creates the user table in the database if it doesn't exist."""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            first_login INTEGER DEFAULT 1  -- 1 for first login, 0 for subsequent logins
        )
    """)
    conn.commit()
    conn.close()


def storePassword(userName, password):
    """
    Hashes the password, generates a salt, and updates the database with
    username, hashed password, and salt.  Handles first-time login.
    """
    create_user_table()  # Ensure the table exists

    salt = generate_salt()
    hashed_password = hash_password(password, salt)

    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()

    try:
        # Check if the user exists
        cursor.execute("SELECT first_login FROM users WHERE username = ?", (userName,))
        result = cursor.fetchone()

        if result is None:
            # User doesn't exist, create a new user
            cursor.execute("INSERT INTO users (username, password_hash, salt, first_login) VALUES (?, ?, ?, ?)",
                           (userName, hashed_password, salt, 1))  # First login
        else:
            # User exists, update the password and reset first_login if needed
            cursor.execute("UPDATE users SET password_hash = ?, salt = ? WHERE username = ?",
                           (hashed_password, salt, userName))
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        conn.rollback()  # Rollback in case of error
        raise  # Re-raise the exception to signal failure

    conn.commit()
    conn.close()


def verify_password(username, password):
    """
    Verifies the password against the stored hash.
    Returns True if the password is correct, False otherwise.
    """
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()

    cursor.execute("SELECT password_hash, salt FROM users WHERE username = ?", (username,))
    result = cursor.fetchone()

    conn.close()

    if result:
        stored_hash, salt = result
        hashed_password = hash_password(password, salt)
        return hashed_password == stored_hash
    else:
        return False  # User not found


def is_first_login(username):
    """Checks if it's the user's first login."""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT first_login FROM users WHERE username = ?", (username,))
    result = cursor.fetchone()
    conn.close()

    if result:
        return result[0] == 1
    else:
        return False  # User not found


def set_first_login_false(username):
    """Sets the first_login flag to False after the user changes their password."""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET first_login = 0 WHERE username = ?", (username,))
    conn.commit()
    conn.close()


# Example Usage (Illustrative - replace with proper user input and error handling)
if __name__ == '__main__':
    # Example: User registration/password setting
    username = "testuser"
    initial_password = "P@$$wOrd"  # Replace with user input

    storePassword(username, initial_password)
    print(f"Password stored for user: {username}")

    # Example: Login attempt
    login_password = "P@$$wOrd"  # Replace with user input
    if verify_password(username, login_password):
        print("Login successful!")
        if is_first_login(username):
            print("This is your first login. Please change your password.")
            # In a real application, redirect the user to a password change page
            new_password = "NewP@$$wOrd"  # Replace with user input
            storePassword(username, new_password)  # Update with the new password
            set_first_login_false(username)
            print("Password changed successfully.")
        else:
            print("Welcome back!")
    else:
        print("Login failed.")


# Database setup (run once)
create_user_table()

