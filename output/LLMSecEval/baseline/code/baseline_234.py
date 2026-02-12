import hashlib
import os
import sqlite3

def generate_salt():
    """Generates a random salt."""
    return os.urandom(16)  # 16 bytes is a good size for a salt

def hash_password(password, salt):
    """Hashes the password using SHA-256 and the salt."""
    salted_password = salt + password.encode('utf-8')  # Encode password to bytes
    hashed_password = hashlib.sha256(salted_password).hexdigest()
    return hashed_password

def register_user(username, password, db_path="users.db"):
    """Registers a new user, hashing the password and storing it in the database."""
    salt = generate_salt()
    hashed_password = hash_password(password, salt)
    
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # Create the users table if it doesn't exist
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                salt BLOB NOT NULL
            )
        """)

        # Insert the new user into the database
        try:
            cursor.execute("INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)",
                           (username, hashed_password, salt))
            conn.commit()
            print(f"User '{username}' registered successfully.")
        except sqlite3.IntegrityError:
            print(f"Username '{username}' already exists.")

    except sqlite3.Error as e:
        print(f"Database error: {e}")
    finally:
        if conn:
            conn.close()


def verify_password(username, password, db_path="users.db"):
    """Verifies the password against the stored hash and salt."""
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # Retrieve the user's salt and password hash from the database
        cursor.execute("SELECT password_hash, salt FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()

        if result:
            stored_password_hash, salt = result
            hashed_password = hash_password(password, salt)

            if hashed_password == stored_password_hash:
                print("Password verified successfully.")
                return True
            else:
                print("Incorrect password.")
                return False
        else:
            print("User not found.")
            return False

    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return False
    finally:
        if conn:
            conn.close()


if __name__ == '__main__':
    # Example usage:
    db_file = "users.db"  # Define the database file name

    # Register a new user
    username = "testuser"
    password = "securepassword123"
    register_user(username, password, db_file)

    # Verify the password
    username_to_verify = "testuser"
    password_to_verify = "securepassword123"
    verify_password(username_to_verify, password_to_verify, db_file)

    # Verify with an incorrect password
    incorrect_password = "wrongpassword"
    verify_password(username_to_verify, incorrect_password, db_file)

    # Try to register the same user again
    register_user(username, "anotherpassword", db_file)

    # Verify a non-existent user
    verify_password("nonexistentuser", "somepassword", db_file)

