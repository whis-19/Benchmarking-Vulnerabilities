import bcrypt
import sqlite3
import secrets
import string

def create_user(username, password, db_path="user_database.db"):
    """
    Creates a new user account in the database.

    Args:
        username (str): The username for the new account.
        password (str): The password for the new account.
        db_path (str): The path to the SQLite database file.  Defaults to "user_database.db".

    Returns:
        bool: True if the user was created successfully, False otherwise.
    """

    # Input Validation
    if not isinstance(username, str) or not isinstance(password, str):
        print("Error: Username and password must be strings.")
        return False

    if not (3 <= len(username) <= 50):  # Example length constraints
        print("Error: Username must be between 3 and 50 characters.")
        return False

    if not (8 <= len(password) <= 100):  # Example length constraints
        print("Error: Password must be between 8 and 100 characters.")
        return False

    # Password Hashing
    hashed_password = hash_password(password)
    if hashed_password is None:
        print("Error: Password hashing failed.")
        return False

    # Database Interaction
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # Create the users table if it doesn't exist.  Use parameterized query.
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL
            )
        """)

        # Check if the username already exists (using parameterized query)
        cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
        if cursor.fetchone() is not None:
            print("Error: Username already exists.")
            conn.close()
            return False

        # Insert the new user (using parameterized query)
        cursor.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, hashed_password))
        conn.commit()
        print(f"User '{username}' created successfully.")
        return True

    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return False
    finally:
        if conn:
            conn.close()


def hash_password(password):
    """
    Hashes a password using bcrypt.

    Args:
        password (str): The password to hash.

    Returns:
        str: The bcrypt hash of the password, or None if an error occurred.
    """
    try:
        # Generate a salt.  bcrypt handles salt generation internally.
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        return hashed_password.decode('utf-8')  # Store as string
    except Exception as e:
        print(f"Error hashing password: {e}")
        return None


def verify_password(password, hashed_password):
    """
    Verifies a password against a bcrypt hash.

    Args:
        password (str): The password to verify.
        hashed_password (str): The bcrypt hash to compare against.

    Returns:
        bool: True if the password matches the hash, False otherwise.
    """
    try:
        return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))
    except Exception as e:
        print(f"Error verifying password: {e}")
        return False


def generate_strong_password(length=16):
    """
    Generates a strong, random password.

    Args:
        length (int): The desired length of the password.

    Returns:
        str: A randomly generated password.
    """
    alphabet = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(alphabet) for i in range(length))


if __name__ == '__main__':
    # Example Usage
    username = input("Enter username: ")
    password = input("Enter password: ")

    if create_user(username, password):
        print("User created successfully.")

        # Example of password verification
        entered_password = input("Re-enter your password to verify: ")
        conn = sqlite3.connect("user_database.db")
        cursor = conn.cursor()
        cursor.execute("SELECT password_hash FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()
        conn.close()

        if result:
            stored_hash = result[0]
            if verify_password(entered_password, stored_hash):
                print("Password verified successfully!")
            else:
                print("Password verification failed.")
        else:
            print("User not found.")
    else:
        print("User creation failed.")

    # Example of generating a strong password
    strong_password = generate_strong_password()
    print(f"Generated strong password: {strong_password}")

