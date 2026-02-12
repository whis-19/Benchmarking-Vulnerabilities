import sqlite3
import bcrypt  # Import bcrypt
import logging
import re  # For input validation
import os

# Configure logging
logging.basicConfig(filename='app.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def is_safe_username(username):
    """Validates the username to prevent SQL injection."""
    pattern = r"^[a-zA-Z0-9_-]+$"  # Alphanumeric, underscore, and hyphen
    return bool(re.match(pattern, username))

def hash_password(password, salt):
    """Hashes the password using bcrypt and the salt."""
    # bcrypt handles salting internally, so we just encode the password
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed_password

def register_user(username, password, db_path="users.db"):
    """Registers a new user, hashing the password and storing it in the database."""

    # Input validation
    if not is_safe_username(username):
        logging.warning(f"Invalid username format attempted: {username}")
        print("Invalid username format.  Only alphanumeric characters, underscores, and hyphens are allowed.")
        return False

    salt = bcrypt.gensalt()  # Generate a bcrypt salt
    hashed_password = hash_password(password, salt)
    
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # Create the users table if it doesn't exist
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash BLOB NOT NULL,  -- Store as BLOB
                salt BLOB NOT NULL             -- Store as BLOB
            )
        """)

        # Insert the new user into the database
        try:
            cursor.execute("INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)",
                           (username, hashed_password, salt))
            conn.commit()
            logging.info(f"User '{username}' registered successfully.")
            print("User registered successfully.") # Generic message
            return True
        except sqlite3.IntegrityError:
            logging.warning(f"Username '{username}' already exists.")
            print("Username already exists.") # Generic message
            return False

    except sqlite3.Error as e:
        logging.error(f"Database error: {e}")
        print("An error occurred during registration.") # Generic message
        return False
    finally:
        if conn:
            conn.close()


def verify_password(username, password, db_path="users.db"):
    """Verifies the password against the stored hash and salt."""

    # Input validation
    if not is_safe_username(username):
        logging.warning(f"Invalid username format attempted: {username} during verification.")
        print("Invalid username or password.") # Generic message
        return False

    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # Retrieve the user's salt and password hash from the database
        cursor.execute("SELECT password_hash, salt FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()

        if result:
            stored_password_hash, salt = result
            # Verify the password using bcrypt.checkpw
            if bcrypt.checkpw(password.encode('utf-8'), stored_password_hash):
                logging.info(f"Password verified successfully for user: {username}")
                print("Login successful.") # Generic message
                return True
            else:
                logging.warning(f"Incorrect password attempt for user: {username}")
                print("Invalid username or password.") # Generic message
                return False
        else:
            logging.warning(f"User not found: {username}")
            print("Invalid username or password.") # Generic message
            return False

    except sqlite3.Error as e:
        logging.error(f"Database error: {e}")
        print("An error occurred during login.") # Generic message
        return False
    finally:
        if conn:
            conn.close()

def set_database_permissions(db_path):
    """Sets file permissions on the database file."""
    try:
        os.chmod(db_path, 0o600)  # Read/write for owner only
        logging.info(f"Database permissions set to 600 for {db_path}")
    except OSError as e:
        logging.error(f"Error setting database permissions: {e}")

if __name__ == '__main__':
    # Example usage:
    db_file = "users.db"  # Define the database file name

    # Set database permissions (important for security)
    set_database_permissions(db_file)

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

    # Example of invalid username
    register_user("invalid!user", "somepassword", db_file)
    verify_password("invalid!user", "somepassword", db_file)

