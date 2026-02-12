import hashlib
import sqlite3
import secrets
import os

# Database configuration
DATABASE_FILE = 'users.db'

# Security parameters
SALT_LENGTH = 16  # Length of the salt in bytes
HASH_ALGORITHM = 'sha256'  # Hashing algorithm to use
ITERATIONS = 100000  # Number of iterations for key derivation


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
                salt TEXT NOT NULL
            )
        ''')
        conn.commit()
    except sqlite3.Error as e:
        print(f"Database error: {e}")
    finally:
        if conn:
            conn.close()


def hash_password(password, salt=None):
    """Hashes the password using a salt and the specified algorithm."""
    if salt is None:
        salt = secrets.token_hex(SALT_LENGTH // 2)  # Generate a random salt

    salted_password = salt + password
    hashed_password = hashlib.pbkdf2_hmac(
        HASH_ALGORITHM,
        salted_password.encode('utf-8'),
        salt.encode('utf-8'),
        ITERATIONS
    ).hex()

    return hashed_password, salt


def register_user(username, password):
    """Registers a new user in the database."""
    conn = None  # Initialize conn to None
    try:
        hashed_password, salt = hash_password(password)

        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO users (username, password_hash, salt)
            VALUES (?, ?, ?)
        ''', (username, hashed_password, salt))
        conn.commit()
        return True  # Registration successful
    except sqlite3.IntegrityError:
        print("Username already exists.")
        return False  # Registration failed (username already exists)
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return False  # Registration failed (database error)
    finally:
        if conn:
            conn.close()


def verify_password(username, password):
    """Verifies the password against the stored hash."""
    conn = None  # Initialize conn to None
    try:
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT password_hash, salt FROM users WHERE username = ?
        ''', (username,))
        result = cursor.fetchone()

        if result:
            stored_hash, salt = result
            hashed_password, _ = hash_password(password, salt)  # Re-hash with the stored salt
            return hashed_password == stored_hash
        else:
            return False  # User not found
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return False  # Verification failed (database error)
    finally:
        if conn:
            conn.close()


def main():
    """Main function to demonstrate registration and verification."""
    create_table()  # Ensure the table exists

    while True:
        print("\nOptions:")
        print("1. Register")
        print("2. Login")
        print("3. Exit")

        choice = input("Enter your choice: ")

        if choice == '1':
            username = input("Enter username: ")
            password = input("Enter password: ")
            if register_user(username, password):
                print("Registration successful!")
            else:
                print("Registration failed.")

        elif choice == '2':
            username = input("Enter username: ")
            password = input("Enter password: ")
            if verify_password(username, password):
                print("Login successful!")
            else:
                print("Login failed.")

        elif choice == '3':
            print("Exiting...")
            break

        else:
            print("Invalid choice. Please try again.")


if __name__ == "__main__":
    main()

