import hashlib
import secrets
import os
import configparser
import sqlite3

# Configuration file path (outside the code directory)
CONFIG_FILE = os.path.join("..", "config", "registration_config.ini")  # Go up one level, into a 'config' directory

def load_config():
    """Loads configuration from the specified file."""
    config = configparser.ConfigParser()
    config.read(CONFIG_FILE)
    return config

def create_database_connection(db_path):
    """Creates a connection to the SQLite database."""
    try:
        conn = sqlite3.connect(db_path)
        return conn
    except sqlite3.Error as e:
        print(f"Error connecting to database: {e}")
        return None

def create_user_table(conn):
    """Creates the user table if it doesn't exist."""
    try:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                first_login INTEGER DEFAULT 1  -- 1 for first login, 0 for subsequent logins
            )
        """)
        conn.commit()
    except sqlite3.Error as e:
        print(f"Error creating user table: {e}")

def generate_salt():
    """Generates a random salt."""
    return secrets.token_hex(16)  # 16 bytes = 32 hex characters

def hash_password(password, salt):
    """Hashes the password using SHA-256 with a salt."""
    salted_password = salt.encode('utf-8') + password.encode('utf-8')
    hashed_password = hashlib.sha256(salted_password).hexdigest()
    return hashed_password

def register_user(username, password, db_conn):
    """Registers a new user."""
    try:
        cursor = db_conn.cursor()

        # Check if the username already exists
        cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
        if cursor.fetchone():
            return "Username already exists."

        salt = generate_salt()
        password_hash = hash_password(password, salt)

        cursor.execute("INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)",
                       (username, password_hash, salt))
        db_conn.commit()
        return "User registered successfully."
    except sqlite3.Error as e:
        print(f"Error registering user: {e}")
        db_conn.rollback()
        return f"Registration failed: {e}"

def verify_password(username, password, db_conn):
    """Verifies the password against the stored hash."""
    try:
        cursor = db_conn.cursor()
        cursor.execute("SELECT password_hash, salt FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()

        if result:
            stored_password_hash, salt = result
            hashed_password = hash_password(password, salt)

            if hashed_password == stored_password_hash:
                return True
            else:
                return False
        else:
            return False  # User not found
    except sqlite3.Error as e:
        print(f"Error verifying password: {e}")
        return False

def change_password_first_login(username, new_password, db_conn):
    """Forces a password change on first login."""
    try:
        cursor = db_conn.cursor()
        cursor.execute("SELECT first_login FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()

        if result and result[0] == 1:  # first_login is 1
            salt = generate_salt()
            new_password_hash = hash_password(new_password, salt)

            cursor.execute("UPDATE users SET password_hash = ?, salt = ?, first_login = 0 WHERE username = ?",
                           (new_password_hash, salt, username))
            db_conn.commit()
            return True
        else:
            return False  # Not a first-time login or user not found
    except sqlite3.Error as e:
        print(f"Error changing password: {e}")
        db_conn.rollback()
        return False

def main():
    """Main function to demonstrate registration and login."""

    # Load configuration
    config = load_config()
    db_path = config.get('database', 'db_path', fallback='users.db')  # Default to 'users.db' if not in config

    # Create database connection
    db_conn = create_database_connection(db_path)
    if not db_conn:
        print("Failed to connect to the database. Exiting.")
        return

    # Create user table
    create_user_table(db_conn)

    while True:
        print("\nRegistration/Login Menu:")
        print("1. Register")
        print("2. Login")
        print("3. Change Password (First Login)")
        print("4. Exit")

        choice = input("Enter your choice: ")

        if choice == '1':
            username = input("Enter username: ")
            password = input("Enter password: ")  # Consider password strength validation here
            result = register_user(username, password, db_conn)
            print(result)

        elif choice == '2':
            username = input("Enter username: ")
            password = input("Enter password: ")
            if verify_password(username, password, db_conn):
                print("Login successful!")
            else:
                print("Login failed.")

        elif choice == '3':
            username = input("Enter username: ")
            new_password = input("Enter new password (required for first login): ")
            if change_password_first_login(username, new_password, db_conn):
                print("Password changed successfully.")
            else:
                print("Password change failed.  Either not a first-time login or user not found.")

        elif choice == '4':
            break
        else:
            print("Invalid choice.")

    # Close database connection
    db_conn.close()

if __name__ == "__main__":
    main()

