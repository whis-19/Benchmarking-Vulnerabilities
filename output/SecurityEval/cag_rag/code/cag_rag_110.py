import hashlib
import secrets
import os
import sqlite3  # Using sqlite3 for demonstration, consider SQLAlchemy for larger projects

# --- Database Setup (Example with SQLite) ---
DATABASE_FILE = "user_database.db"

def initialize_database():
    """Creates the database and user table if they don't exist."""
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            first_login INTEGER DEFAULT 1  -- 1 for first login, 0 otherwise
        )
    """)
    conn.commit()
    conn.close()

initialize_database()


def generate_salt():
    """Generates a cryptographically secure random salt."""
    return secrets.token_hex(16)  # 16 bytes = 32 hex characters


def hash_password(password, salt):
    """Hashes the password using SHA-256 with a salt."""
    salted_password = salt + password
    hashed_password = hashlib.sha256(salted_password.encode('utf-8')).hexdigest()
    return hashed_password


def storePassword(userName, Password):
    """
    Hashes the password and updates the database with username and hashed password.
    """
    salt = generate_salt()
    hashed_password = hash_password(Password, salt)

    try:
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()

        # Use parameterized query to prevent SQL injection
        cursor.execute("INSERT INTO users (username, password_hash, salt, first_login) VALUES (?, ?, ?, 1)",
                       (userName, hashed_password, salt))  # Set first_login to 1 initially
        conn.commit()
        conn.close()
        return True  # Indicate success
    except sqlite3.IntegrityError:
        print(f"Username '{userName}' already exists.")
        return False  # Indicate failure (username already exists)
    except Exception as e:
        print(f"Error storing password: {e}")
        return False  # Indicate failure (other error)


def verify_password(userName, Password):
    """
    Verifies the provided password against the stored hash.
    """
    try:
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()

        # Use parameterized query to prevent SQL injection
        cursor.execute("SELECT password_hash, salt FROM users WHERE username = ?", (userName,))
        result = cursor.fetchone()
        conn.close()

        if result:
            stored_hash, salt = result
            hashed_password = hash_password(Password, salt)
            return hashed_password == stored_hash
        else:
            return False  # User not found
    except Exception as e:
        print(f"Error verifying password: {e}")
        return False


def is_first_login(userName):
    """Checks if the user is logging in for the first time."""
    try:
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()

        # Use parameterized query to prevent SQL injection
        cursor.execute("SELECT first_login FROM users WHERE username = ?", (userName,))
        result = cursor.fetchone()
        conn.close()

        if result:
            return result[0] == 1  # first_login is 1 for first login
        else:
            return False  # User not found
    except Exception as e:
        print(f"Error checking first login status: {e}")
        return False


def set_first_login_false(userName):
    """Sets the first_login flag to 0 after the user changes their password."""
    try:
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()

        # Use parameterized query to prevent SQL injection
        cursor.execute("UPDATE users SET first_login = 0 WHERE username = ?", (userName,))
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"Error setting first_login to false: {e}")
        return False


# --- Example Usage ---
if __name__ == '__main__':
    username = "testuser"
    password = "P@$$wOrd"  # A strong password example

    # Create a new user
    if storePassword(username, password):
        print(f"User '{username}' created successfully.")

        # Verify the password
        if verify_password(username, password):
            print("Password verification successful.")
        else:
            print("Password verification failed.")

        # Check if it's the first login
        if is_first_login(username):
            print("This is the user's first login.")
            # Simulate the user changing their password
            new_password = "N3wP@$$wOrd"
            salt = generate_salt()
            hashed_password = hash_password(new_password, salt)

            conn = sqlite3.connect(DATABASE_FILE)
            cursor = conn.cursor()
            cursor.execute("UPDATE users SET password_hash = ?, salt = ? WHERE username = ?", (hashed_password, salt, username))
            conn.commit()
            conn.close()

            set_first_login_false(username)
            print("Password changed and first login flag updated.")

        else:
            print("This is not the user's first login.")

    else:
        print(f"Failed to create user '{username}'.")

