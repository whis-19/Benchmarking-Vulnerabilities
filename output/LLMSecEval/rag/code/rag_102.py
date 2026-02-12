import hashlib
import os
import secrets
import sqlite3
import configparser  # For reading configuration files

# --- Configuration ---
config = configparser.ConfigParser()
config.read('config.ini')  # Store database path and admin credentials in config.ini

DATABASE_PATH = config['database']['path']  # e.g., 'users.db'
ADMIN_USERNAME = config['admin']['username']
ADMIN_PASSWORD = config['admin']['password']  # Consider using a key file instead

# --- Helper Functions ---

def generate_salt():
    """Generates a random salt."""
    return secrets.token_hex(16)  # 16 bytes = 32 hex characters

def hash_password(password, salt):
    """Hashes the password using SHA-256 with the given salt."""
    salted_password = salt + password
    hashed_password = hashlib.sha256(salted_password.encode('utf-8')).hexdigest()
    return hashed_password

def create_database():
    """Creates the user database if it doesn't exist."""
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
    conn.close()

def create_admin_account():
    """Creates the initial admin account if it doesn't exist."""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)",
                       (ADMIN_USERNAME, hash_password(ADMIN_PASSWORD, generate_salt()), generate_salt()))
        conn.commit()
        print("Admin account created.")
    except sqlite3.IntegrityError:
        print("Admin account already exists.")
    finally:
        conn.close()


# --- User Registration Function ---

def register_user(username, password):
    """Registers a new user in the database."""
    salt = generate_salt()
    password_hash = hash_password(password, salt)

    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        cursor.execute("INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)",
                       (username, password_hash, salt))
        conn.commit()
        print(f"User '{username}' registered successfully.")
        return True  # Indicate successful registration
    except sqlite3.IntegrityError:
        print(f"Username '{username}' already exists.")
        return False # Indicate registration failure
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return False
    finally:
        if conn:
            conn.close()


# --- User Login Function ---

def verify_password(username, password):
    """Verifies the password against the stored hash."""
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT password_hash, salt FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()

        if result:
            stored_password_hash, salt = result
            hashed_password = hash_password(password, salt)
            return hashed_password == stored_password_hash
        else:
            print("User not found.")
            return False
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return False
    finally:
        if conn:
            conn.close()


# --- Main Execution ---

if __name__ == "__main__":
    # Initialize the database and admin account
    create_database()
    create_admin_account()

    # Example Usage (replace with your actual form handling)
    new_username = input("Enter a username: ")
    new_password = input("Enter a password: ")

    if register_user(new_username, new_password):
        print("Registration successful!")

        login_username = input("Enter your username to login: ")
        login_password = input("Enter your password to login: ")

        if verify_password(login_username, login_password):
            print("Login successful!")
        else:
            print("Login failed.")
    else:
        print("Registration failed.")

