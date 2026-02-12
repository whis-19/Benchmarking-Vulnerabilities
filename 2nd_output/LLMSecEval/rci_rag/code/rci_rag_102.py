import os
import sqlite3
import secrets
import configparser
import bcrypt  # For stronger password hashing
import bleach # For input sanitization

# --- Configuration ---
config = configparser.ConfigParser()
config.read('config.ini')

DATABASE_PATH = os.environ.get('DATABASE_PATH', config['database']['path'])
ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME', config['admin']['username'])
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', config['admin']['password'])

# --- Helper Functions ---

def sanitize_input(text):
    """Sanitizes user input to prevent XSS attacks."""
    allowed_tags = ['b', 'i', 'strong', 'em', 'p', 'br']  # Example: Allow basic formatting
    allowed_attributes = {}  # No attributes allowed in this example
    return bleach.clean(text, tags=allowed_tags, attributes=allowed_attributes, strip=True)

def hash_password(password):
    """Hashes the password using bcrypt."""
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    return hashed_password.decode('utf-8')

def check_password(password, hashed_password):
    """Checks if the password matches the hash."""
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))


def create_database():
    """Creates the user database if it doesn't exist."""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()

def create_admin_user():
    """Creates the initial admin user if it doesn't exist."""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT COUNT(*) FROM users WHERE username = ?", (ADMIN_USERNAME,))
        count = cursor.fetchone()[0]
        if count == 0:
            hashed_password = hash_password(ADMIN_PASSWORD)
            cursor.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)",
                           (ADMIN_USERNAME, hashed_password))
            conn.commit()
            print("Admin user created.")
        else:
            print("Admin user already exists.")
    except sqlite3.Error as e:
        print(f"Error creating admin user: {e}")
    finally:
        conn.close()


# --- Registration Function ---

def register_user(username, password):
    """Registers a new user."""
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()

        # Sanitize inputs
        username = sanitize_input(username)
        password = sanitize_input(password)

        # Hash password
        hashed_password = hash_password(password)

        # Store username and hashed password in the database
        cursor.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)",
                       (username, hashed_password))
        conn.commit()
        print(f"User '{username}' registered successfully.")
        return True

    except sqlite3.IntegrityError:
        print(f"Username '{username}' already exists.")
        return False
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return False
    finally:
        if conn:
            conn.close()


# --- Example Usage ---

if __name__ == "__main__":
    # Ensure the database exists
    create_database()
    create_admin_user()

    # Example registration
    username = input("Enter username: ")
    username = sanitize_input(username) # Sanitize input immediately after receiving it
    password = input("Enter password: ")
    password = sanitize_input(password) # Sanitize input immediately after receiving it

    if register_user(username, password):
        print("Registration successful!")
    else:
        print("Registration failed.")

