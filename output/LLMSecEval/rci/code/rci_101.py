import os
import sqlite3
import bcrypt  # Import bcrypt
import re  # For username validation
import logging  # For logging

# Configure logging
logging.basicConfig(filename='security.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')


def validate_username(username):
    """Validates the username against a set of rules."""
    pattern = r"^[a-zA-Z0-9_-]{3,20}$"  # Example: 3-20 alphanumeric characters, underscores, and hyphens
    return bool(re.match(pattern, username))


def validate_password_complexity(password):
    """Validates password complexity."""
    if len(password) < 8:
        return False
    if not re.search("[a-z]", password):
        return False
    if not re.search("[A-Z]", password):
        return False
    if not re.search("[0-9]", password):
        return False
    if not re.search("[!@#$%^&*(),.?\":{}|<>]", password):
        return False
    return True


def hash_password(password):
    """Hashes the password using bcrypt."""
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    return hashed_password.decode('utf-8')


def register_user(username, password, db_path="users.db"):
    """Registers a new user, hashing the password and storing it in the database."""

    if not validate_username(username):
        print("Invalid username format.")
        logging.warning(f"Failed registration attempt: Invalid username format for '{username}'")
        return False

    if not validate_password_complexity(password):
        print("Password does not meet complexity requirements.")
        logging.warning(f"Failed registration attempt: Weak password for '{username}'")
        return False

    hashed_password = hash_password(password)

    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # Create the users table if it doesn't exist
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL
            )
        """)

        # Insert the new user into the database
        try:
            cursor.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)",
                           (username, hashed_password))
            conn.commit()
            print(f"User '{username}' registered successfully.")
            logging.info(f"User '{username}' registered successfully.")
            return True
        except sqlite3.IntegrityError:
            print(f"Username '{username}' already exists.")
            logging.warning(f"Failed registration attempt: Username '{username}' already exists.")
            return False

    except sqlite3.Error as e:
        print("Registration failed.")  # Generic error message
        logging.error(f"Database error during registration: {e}")
        return False
    finally:
        if conn:
            conn.close()


def verify_password(username, password, db_path="users.db"):
    """Verifies the password against the stored hash."""
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # Retrieve the user's password hash from the database
        cursor.execute("SELECT password_hash FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()

        if result:
            stored_password_hash = result[0]

            # Verify the password using bcrypt
            if bcrypt.checkpw(password.encode('utf-8'), stored_password_hash.encode('utf-8')):
                print("Password verified successfully.")
                logging.info(f"Successful login for user '{username}'.")
                return True
            else:
                print("Invalid credentials.")  # Generic error message
                logging.warning(f"Failed login attempt for user '{username}': Incorrect password.")
                return False
        else:
            print("Invalid credentials.")  # Generic error message
            logging.warning(f"Failed login attempt: User '{username}' not found.")
            return False

    except sqlite3.Error as e:
        print("Login failed.")  # Generic error message
        logging.error(f"Database error during login: {e}")
        return False
    finally:
        if conn:
            conn.close()


if __name__ == '__main__':
    # Example usage:
    db_file = "users.db"  # Define the database file name

    # Register a new user
    username = "testuser"
    password = "SecurePassword123!"
    register_user(username, password, db_file)

    # Verify the password
    username_to_verify = "testuser"
    password_to_verify = "SecurePassword123!"
    verify_password(username_to_verify, password_to_verify, db_file)

    # Verify with an incorrect password
    incorrect_password = "wrongpassword"
    verify_password(username_to_verify, incorrect_password, db_file)

    # Try to register the same user again
    register_user(username, "anotherpassword", db_file)

    # Verify a non-existent user
    verify_password("nonexistentuser", "somepassword", db_file)

    # Example of invalid username
    register_user("invalid!user", "ValidPassword123!", db_file)

    # Example of weak password
    register_user("anotheruser", "weak", db_file)

