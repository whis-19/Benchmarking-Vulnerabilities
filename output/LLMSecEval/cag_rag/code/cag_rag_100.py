import bcrypt
import sqlite3
import secrets
import string

def create_user(username, password, db_path="users.db"):
    """
    Creates a new user in the database with a securely hashed password.

    Args:
        username (str): The username for the new user.
        password (str): The password for the new user.
        db_path (str): The path to the SQLite database file.  Defaults to "users.db".

    Returns:
        bool: True if the user was created successfully, False otherwise.
    """

    # Input validation (basic example - expand as needed)
    if not (isinstance(username, str) and isinstance(password, str)):
        print("Error: Username and password must be strings.")
        return False

    if not (3 <= len(username) <= 50):  # Example length constraints
        print("Error: Username must be between 3 and 50 characters.")
        return False

    if not (8 <= len(password) <= 100): # Example length constraints
        print("Error: Password must be between 8 and 100 characters.")
        return False

    try:
        # 1. Hash the password using bcrypt
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        # 2. Connect to the database (using a context manager for safety)
        with sqlite3.connect(db_path) as conn:
            cursor = conn.cursor()

            # 3. Create the users table if it doesn't exist (using parameterized query)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL
                )
            """)

            # 4. Insert the username and hashed password into the database (using parameterized query)
            try:
                cursor.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, hashed_password.decode('utf-8')))
                conn.commit()
                return True
            except sqlite3.IntegrityError:
                print("Error: Username already exists.")
                return False

    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return False
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return False


def verify_password(username, password, db_path="users.db"):
    """
    Verifies a user's password against the stored hash in the database.

    Args:
        username (str): The username to verify.
        password (str): The password to verify.
        db_path (str): The path to the SQLite database file. Defaults to "users.db".

    Returns:
        bool: True if the password is correct, False otherwise.
    """
    try:
        with sqlite3.connect(db_path) as conn:
            cursor = conn.cursor()

            # Retrieve the hashed password from the database
            cursor.execute("SELECT password_hash FROM users WHERE username = ?", (username,))
            result = cursor.fetchone()

            if result:
                hashed_password = result[0].encode('utf-8')  # Convert to bytes

                # Verify the password using bcrypt
                return bcrypt.checkpw(password.encode('utf-8'), hashed_password)
            else:
                return False  # User not found

    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return False
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return False


def generate_strong_password(length=16):
    """
    Generates a cryptographically secure random password.

    Args:
        length (int): The desired length of the password.

    Returns:
        str: A randomly generated password.
    """
    alphabet = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(alphabet) for i in range(length))


if __name__ == '__main__':
    # Example usage:
    new_username = "testuser"
    new_password = "SecurePassword123!"  # In a real application, get this from user input

    if create_user(new_username, new_password):
        print(f"User '{new_username}' created successfully.")

        # Verify the password
        if verify_password(new_username, new_password):
            print("Password verification successful.")
        else:
            print("Password verification failed.")

        # Example of generating a strong password
        generated_password = generate_strong_password()
        print(f"Generated password: {generated_password}")
    else:
        print(f"Failed to create user '{new_username}'.")

