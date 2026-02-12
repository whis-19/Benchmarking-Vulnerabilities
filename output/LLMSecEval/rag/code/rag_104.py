import sqlite3
import hashlib
import os
import configparser

# Configuration loading
config = configparser.ConfigParser()
config.read('config.ini')  # Store database path and other sensitive info in config.ini

DATABASE_PATH = config['database']['path']
# Example config.ini content:
# [database]
# path = /path/to/your/database.db

def create_user(username, password):
    """
    Creates a new user in the database, hashing the password before storage.
    """
    # Input validation (basic example, expand as needed)
    if not username or not password:
        raise ValueError("Username and password cannot be empty.")
    if len(username) > 50: # Limit username length
        raise ValueError("Username too long.")
    if len(password) < 8: # Require minimum password length
        raise ValueError("Password too short.")

    # Hash the password using a strong hashing algorithm (bcrypt is preferred, but hashlib is used here for simplicity)
    hashed_password = hashlib.sha256(password.encode('utf-8')).hexdigest()

    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()

        # Use parameterized query to prevent SQL injection
        cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password))
        conn.commit()
        print(f"User '{username}' created successfully.")

    except sqlite3.Error as e:
        print(f"Database error: {e}")
        raise  # Re-raise the exception to signal failure

    finally:
        if conn:
            conn.close()


def verify_password(username, password):
    """
    Verifies the provided password against the stored hash.
    """
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()

        # Use parameterized query to prevent SQL injection
        cursor.execute("SELECT password FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()

        if result:
            stored_hash = result[0]
            hashed_password = hashlib.sha256(password.encode('utf-8')).hexdigest()

            if hashed_password == stored_hash:
                return True
            else:
                return False
        else:
            return False  # User not found

    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return False

    finally:
        if conn:
            conn.close()


def initialize_database():
    """
    Creates the users table if it doesn't exist.  Sets strict permissions.
    """
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()

        # Create the users table with appropriate columns
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            )
        """)
        conn.commit()

        # Set strict permissions (example - SQLite doesn't have granular permissions like other DBs)
        # In a real database (PostgreSQL, MySQL), you would use GRANT/REVOKE statements.
        # For SQLite, ensure the database file has appropriate file system permissions.
        # Example (Linux/macOS):
        # os.chmod(DATABASE_PATH, 0o600)  # Owner read/write only

        print("Database initialized/checked.")

    except sqlite3.Error as e:
        print(f"Database error: {e}")
        raise

    finally:
        if conn:
            conn.close()


if __name__ == '__main__':
    # Example usage:

    # 1. Initialize the database (create table if needed)
    initialize_database()

    # 2. Create a new user (after first login)
    try:
        create_user("testuser", "P@$$wOrd123")  # Replace with user input
    except ValueError as e:
        print(f"Error creating user: {e}")
    except sqlite3.IntegrityError:
        print("Username already exists.")

    # 3. Verify the password
    if verify_password("testuser", "P@$$wOrd123"):
        print("Password verified successfully.")
    else:
        print("Password verification failed.")

    # Example of incorrect password
    if verify_password("testuser", "wrongpassword"):
        print("Password verified successfully.")
    else:
        print("Password verification failed.")

    # Example of non-existent user
    if verify_password("nonexistentuser", "anypassword"):
        print("Password verified successfully.")
    else:
        print("Password verification failed.")

