import sqlite3
import hashlib
import os
import secrets
import configparser

# --- Configuration Loading ---
config = configparser.ConfigParser()
config.read('config.ini')  # Store database path and other sensitive info in config.ini

db_path = config['DATABASE']['path']  # e.g., 'users.db'
# --- Database Initialization ---
def create_table():
    """Creates the users table if it doesn't exist."""
    try:
        conn = sqlite3.connect(db_path)
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
    except sqlite3.Error as e:
        print(f"Database error: {e}")  # Consider logging this to a file instead of printing
    finally:
        if conn:
            conn.close()

create_table()  # Ensure the table exists on startup

# --- Password Hashing Functions ---
def generate_salt():
    """Generates a random salt."""
    return secrets.token_hex(16)  # 16 bytes = 32 hex characters

def hash_password(password, salt):
    """Hashes the password using SHA-256 and the salt."""
    salted_password = salt + password
    hashed_password = hashlib.sha256(salted_password.encode('utf-8')).hexdigest()
    return hashed_password

# --- User Registration ---
def register_user(username, password):
    """Registers a new user."""
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        salt = generate_salt()
        password_hash = hash_password(password, salt)

        cursor.execute("INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)",
                       (username, password_hash, salt))
        conn.commit()
        return True  # Registration successful
    except sqlite3.IntegrityError:
        print("Username already exists.") #Consider logging this to a file instead of printing
        return False # Registration failed (username exists)
    except sqlite3.Error as e:
        print(f"Database error: {e}") #Consider logging this to a file instead of printing
        return False # Registration failed (database error)
    finally:
        if conn:
            conn.close()

# --- User Login ---
def verify_password(username, password):
    """Verifies the password for a given user."""
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        cursor.execute("SELECT password_hash, salt FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()

        if result:
            stored_password_hash, salt = result
            hashed_password = hash_password(password, salt)

            return hashed_password == stored_password_hash
        else:
            return False  # User not found
    except sqlite3.Error as e:
        print(f"Database error: {e}") #Consider logging this to a file instead of printing
        return False # Login failed (database error)
    finally:
        if conn:
            conn.close()

# --- Example Usage ---
if __name__ == '__main__':
    # Example registration
    username = "testuser"
    password = "secure_password123"  # Replace with a strong password

    if register_user(username, password):
        print("User registered successfully.")
    else:
        print("User registration failed.")

    # Example login
    if verify_password(username, password):
        print("Login successful.")
    else:
        print("Login failed.")

