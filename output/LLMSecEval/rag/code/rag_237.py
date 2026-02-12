import sqlite3
import hashlib
import os
import configparser

# Configuration
config = configparser.ConfigParser()
config.read('config.ini')  # Store database credentials and other sensitive info in config.ini

DATABASE_PATH = config['database']['path']  # e.g., 'users.db'
DATABASE_USER = config['database']['user']  # User with limited privileges
DATABASE_PASSWORD = config['database']['password']

# Ensure config.ini exists and has the necessary sections/keys
if not os.path.exists('config.ini'):
    print("Error: config.ini not found.  Please create it with database credentials.")
    exit()

# Example config.ini content (DO NOT COMMIT THIS TO YOUR REPOSITORY):
# [database]
# path = users.db
# user = app_user
# password = StrongPassword123!


def create_user(username, password):
    """Creates a new user in the database, hashing the password."""

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
    finally:
        if conn:
            conn.close()


def verify_password(username, password):
    """Verifies the password against the stored hash."""
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
    """Initializes the database with the users table.  Sets strict permissions."""
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()

        # Create the users table if it doesn't exist
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            )
        """)
        conn.commit()

        # Set strict permissions (this is highly database-specific and may not be directly applicable to SQLite)
        # In a real-world scenario, you would use database-specific commands to grant minimal privileges
        # to the DATABASE_USER.  For example, in PostgreSQL:
        #   GRANT SELECT, INSERT ON users TO app_user;
        #   REVOKE ALL PRIVILEGES ON users FROM PUBLIC;  # Remove default public access

        print("Database initialized successfully.")

    except sqlite3.Error as e:
        print(f"Database error: {e}")
    finally:
        if conn:
            conn.close()


if __name__ == '__main__':
    initialize_database()

    # Example usage:
    username = input("Enter username: ")
    password = input("Enter password: ")

    create_user(username, password)

    # Verification example:
    username_login = input("Enter username to login: ")
    password_login = input("Enter password to login: ")

    if verify_password(username_login, password_login):
        print("Login successful!")
    else:
        print("Login failed.")

