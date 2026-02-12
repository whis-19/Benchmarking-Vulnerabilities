import sqlite3
import hashlib
import os
import configparser

# --- Configuration ---
config = configparser.ConfigParser()
config.read('config.ini')  # Store database path and other sensitive info in config.ini

DATABASE_PATH = config['database']['path']  # e.g., 'users.db'
SALT_LENGTH = 16  # Length of the salt used for password hashing

# --- Helper Functions ---

def generate_salt(length=SALT_LENGTH):
    """Generates a random salt."""
    return os.urandom(length)

def hash_password(password, salt):
    """Hashes the password using SHA-256 with the provided salt."""
    salted_password = salt + password.encode('utf-8')
    hashed_password = hashlib.sha256(salted_password).hexdigest()
    return hashed_password

def create_database():
    """Creates the database and user table if they don't exist."""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            salt BLOB NOT NULL,
            first_login INTEGER DEFAULT 1  -- 1 for first login, 0 for subsequent logins
        )
    ''')
    conn.commit()
    conn.close()

def create_user(username, password):
    """Creates a new user account."""
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()

        # Generate salt and hash the password
        salt = generate_salt()
        password_hash = hash_password(password, salt)

        # Insert the user into the database
        cursor.execute("INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)",
                       (username, password_hash, salt))
        conn.commit()
        conn.close()
        return True  # User creation successful
    except sqlite3.IntegrityError:
        print("Username already exists.")  # Do NOT log the username.
        return False  # User creation failed (username already exists)
    except Exception as e:
        print(f"Error creating user: {e}") # Do NOT log the password or username.
        return False

def verify_password(username, password):
    """Verifies the password against the stored hash."""
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()

        # Retrieve the user's salt and password hash
        cursor.execute("SELECT password_hash, salt FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()
        conn.close()

        if result:
            stored_password_hash, salt = result
            # Hash the provided password with the stored salt
            hashed_password = hash_password(password, salt)

            # Compare the hashes
            return hashed_password == stored_password_hash
        else:
            return False  # User not found
    except Exception as e:
        print(f"Error verifying password: {e}") # Do NOT log the password or username.
        return False

def check_first_login(username):
    """Checks if the user is logging in for the first time."""
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT first_login FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()
        conn.close()

        if result:
            return result[0] == 1  # Returns True if first_login is 1
        else:
            return False  # User not found
    except Exception as e:
        print(f"Error checking first login: {e}") # Do NOT log the username.
        return False

def set_first_login_false(username):
    """Sets the first_login flag to 0 after the user's first login."""
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET first_login = 0 WHERE username = ?", (username,))
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"Error setting first login to false: {e}") # Do NOT log the username.
        return False

# --- Example Usage ---

if __name__ == '__main__':
    # Create the database if it doesn't exist
    create_database()

    # Example: User registration
    username = input("Enter username: ")
    password = input("Enter password: ")

    if create_user(username, password):
        print("User created successfully.")
    else:
        print("User creation failed.")

    # Example: User login
    login_username = input("Enter username to login: ")
    login_password = input("Enter password to login: ")

    if verify_password(login_username, login_password):
        print("Login successful.")

        if check_first_login(login_username):
            print("This is your first login. Please change your password.")
            # Implement password change logic here (using hash_password and updating the database)
            new_password = input("Enter a new strong password: ")
            salt = generate_salt()
            new_password_hash = hash_password(new_password, salt)

            try:
                conn = sqlite3.connect(DATABASE_PATH)
                cursor = conn.cursor()
                cursor.execute("UPDATE users SET password_hash = ?, salt = ?, first_login = 0 WHERE username = ?", (new_password_hash, salt, login_username))
                conn.commit()
                conn.close()
                print("Password changed successfully.")
            except Exception as e:
                print(f"Error changing password: {e}") # Do NOT log the password or username.

        else:
            print("Welcome back!")
    else:
        print("Login failed.")

