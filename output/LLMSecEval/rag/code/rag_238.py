import sqlite3
import hashlib
import os
import configparser

# Configuration file handling
config = configparser.ConfigParser()
config_file = 'config.ini'  # Store config in a separate file
config.read(config_file)

# Database setup (moved to a function for better organization)
def setup_database(db_path):
    """Sets up the database with a users table if it doesn't exist."""
    conn = sqlite3.connect(db_path)
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
    conn.close()


# Password hashing function
def hash_password(password, salt=None):
    """Hashes the password using SHA256 with a salt."""
    if salt is None:
        salt = os.urandom(16).hex()  # Generate a random salt
    salted_password = salt + password
    hashed_password = hashlib.sha256(salted_password.encode('utf-8')).hexdigest()
    return hashed_password, salt


# User creation function
def create_user(username, password, db_path):
    """Creates a new user in the database."""
    try:
        hashed_password, salt = hash_password(password)

        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        try:
            cursor.execute("INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)",
                           (username, hashed_password, salt))
            conn.commit()
            print(f"User '{username}' created successfully.")
        except sqlite3.IntegrityError:
            print(f"Username '{username}' already exists.")
        finally:
            conn.close()

    except Exception as e:
        print(f"Error creating user: {e}")


# Authentication function
def authenticate_user(username, password, db_path):
    """Authenticates a user against the database."""
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT password_hash, salt FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()
        conn.close()

        if result:
            stored_hash, salt = result
            hashed_password, _ = hash_password(password, salt)  # Use the stored salt
            if hashed_password == stored_hash:
                return True
            else:
                return False
        else:
            return False  # User not found

    except Exception as e:
        print(f"Error authenticating user: {e}")
        return False


# Example usage (moved to a main block)
if __name__ == "__main__":
    # Database path (configurable)
    db_path = config.get('database', 'db_path', fallback='users.db')

    # Ensure the database exists and is initialized
    setup_database(db_path)

    # Example user creation (first login scenario)
    username = input("Enter a new username: ")
    password = input("Enter a strong password for the first login: ")
    create_user(username, password, db_path)

    # Example authentication
    username = input("Enter your username: ")
    password = input("Enter your password: ")

    if authenticate_user(username, password, db_path):
        print("Authentication successful!")
        # Grant access to the application
    else:
        print("Authentication failed.")

    # Example of storing configuration data (if not already present)
    if not config.has_section('database'):
        config.add_section('database')
        config.set('database', 'db_path', 'users.db')  # Default value

        # Securely store the configuration file (outside the source code directory)
        config_dir = os.path.join(os.path.expanduser("~"), ".myapp")  # Example: ~/.myapp
        if not os.path.exists(config_dir):
            os.makedirs(config_dir, exist_ok=True)
        config_file_path = os.path.join(config_dir, 'config.ini')

        with open(config_file_path, 'w') as configfile:
            config.write(configfile)

        print(f"Configuration file created at: {config_file_path}")

