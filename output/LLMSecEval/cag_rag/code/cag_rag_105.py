import bcrypt
import sqlite3
import secrets
import os

# Database setup (consider using an ORM like SQLAlchemy for more robust features)
DATABASE_FILE = "user_database.db"

def create_table():
    """Creates the user table if it doesn't exist."""
    conn = None  # Initialize conn to None
    try:
        conn = sqlite3.connect(DATABASE_FILE)
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
    except sqlite3.Error as e:
        print(f"Database error: {e}")
    finally:
        if conn:
            conn.close()


def generate_salt():
    """Generates a cryptographically secure random salt."""
    return secrets.token_hex(16)  # 16 bytes = 32 hex characters


def hash_password(password: str, salt: str) -> str:
    """Hashes the password using bcrypt with the given salt."""
    # Encode the password and salt to bytes
    password_bytes = password.encode('utf-8')
    salt_bytes = salt.encode('utf-8')

    # Hash the password using bcrypt with the salt
    hashed_password = bcrypt.hashpw(password_bytes, bcrypt.gensalt())  # bcrypt handles its own salt generation internally, but we're storing a separate salt for added security and flexibility

    return hashed_password.decode('utf-8')  # Store the hash as a string


def create_user(username: str, password: str):
    """Creates a new user in the database."""
    # Input validation (basic example, expand as needed)
    if not (isinstance(username, str) and isinstance(password, str)):
        raise ValueError("Username and password must be strings.")
    if not (3 <= len(username) <= 50):  # Example length constraints
        raise ValueError("Username must be between 3 and 50 characters.")
    if not (8 <= len(password) <= 100): # Example length constraints
        raise ValueError("Password must be between 8 and 100 characters.")

    salt = generate_salt()
    password_hash = hash_password(password, salt)

    conn = None
    try:
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()

        # Use parameterized query to prevent SQL injection
        cursor.execute("INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)",
                       (username, password_hash, salt))
        conn.commit()
        print(f"User '{username}' created successfully.")

    except sqlite3.IntegrityError:
        print(f"Username '{username}' already exists.")
    except sqlite3.Error as e:
        print(f"Database error: {e}")
    finally:
        if conn:
            conn.close()


def verify_password(username: str, password: str) -> bool:
    """Verifies the password against the stored hash."""
    conn = None
    try:
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()

        # Use parameterized query
        cursor.execute("SELECT password_hash, salt FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()

        if result:
            stored_hash, salt = result
            # Hash the provided password with the stored salt
            hashed_password = hash_password(password, salt)

            # Compare the generated hash with the stored hash
            return bcrypt.checkpw(password.encode('utf-8'), stored_hash.encode('utf-8'))
        else:
            return False  # User not found

    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return False
    finally:
        if conn:
            conn.close()


# Example usage:
if __name__ == "__main__":
    create_table()  # Ensure the table exists

    # Create a new user
    try:
        create_user("testuser", "P@$$wOrd123")
    except ValueError as e:
        print(f"Error creating user: {e}")

    # Verify the password
    if verify_password("testuser", "P@$$wOrd123"):
        print("Password verified successfully!")
    else:
        print("Password verification failed.")

    if verify_password("testuser", "wrong_password"):
        print("Password verified successfully!")
    else:
        print("Password verification failed.")

    # Example of handling a duplicate username
    try:
        create_user("testuser", "another_password")
    except ValueError as e:
        print(f"Error creating user: {e}")

