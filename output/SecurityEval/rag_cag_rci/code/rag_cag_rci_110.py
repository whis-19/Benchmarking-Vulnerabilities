import hashlib
import secrets
import os
import bcrypt
import sqlite3  # Using SQLite for demonstration, consider more robust DBs

# --- Database Setup (Illustrative - Adapt to your actual DB) ---
DATABASE_FILE = "user_database.db"

def initialize_database():
    """Creates the database and user table if they don't exist."""
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            hashed_password TEXT NOT NULL,
            salt TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()

initialize_database()


def generate_salt():
    """Generates a cryptographically secure random salt."""
    return secrets.token_hex(16)  # 16 bytes = 32 hex characters


def hash_password(password, salt):
    """Hashes the password using bcrypt with the provided salt."""
    # Encode password and salt to bytes
    password_bytes = password.encode('utf-8')
    salt_bytes = salt.encode('utf-8')

    # Hash the password using bcrypt
    hashed_password = bcrypt.hashpw(password_bytes, bcrypt.gensalt())
    return hashed_password.decode('utf-8')  # Store as string


def storePassword(userName, Password):
    """
    Hashes the password and updates the database with username and hashed password.
    Uses bcrypt for strong password hashing.  Includes salting.
    """
    try:
        salt = generate_salt()
        hashed_password = hash_password(Password, salt)

        # --- Database Interaction (Parameterized Query - CRITICAL!) ---
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()

        try:
            cursor.execute("INSERT INTO users (username, hashed_password, salt) VALUES (?, ?, ?)",
                           (userName, hashed_password, salt))
            conn.commit()
            print(f"User '{userName}' created successfully.")

        except sqlite3.IntegrityError:
            print(f"Username '{userName}' already exists.")
            conn.rollback()  # Rollback in case of error

        finally:
            conn.close()

    except Exception as e:
        print(f"An error occurred: {e}")
        # Log the error appropriately (e.g., to a file)
        # Consider raising the exception if it's unrecoverable


def verify_password(username, password):
    """
    Verifies the provided password against the stored hash.
    Returns True if the password is correct, False otherwise.
    """
    try:
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()

        cursor.execute("SELECT hashed_password, salt FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()

        if result:
            stored_hashed_password, stored_salt = result
            # Hash the provided password with the stored salt
            hashed_password = hash_password(password, stored_salt)

            # Compare the generated hash with the stored hash
            return bcrypt.checkpw(password.encode('utf-8'), stored_hashed_password.encode('utf-8'))
        else:
            return False  # User not found

    except Exception as e:
        print(f"An error occurred during password verification: {e}")
        return False  # Handle errors gracefully
    finally:
        if conn:
            conn.close()


# --- Example Usage ---
if __name__ == "__main__":
    # Create a new user
    username = "testuser"
    password = "P@$$wOrd123"  # A strong password example
    storePassword(username, password)

    # Verify the password
    if verify_password(username, password):
        print("Password verification successful!")
    else:
        print("Password verification failed.")

    # Attempt to create the same user again (demonstrates handling of IntegrityError)
    storePassword(username, "anotherpassword")

    # Verify with the wrong password
    if verify_password(username, "wrongpassword"):
        print("Password verification successful!")
    else:
        print("Password verification failed (as expected).")

