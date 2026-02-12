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
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    try:
        # Database Connection
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # Create table if it doesn't exist (do this only once, ideally in a separate setup script)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                hashed_password TEXT NOT NULL
            )
        """)

        # Parameterized Query (SQL Injection Prevention)
        try:
            cursor.execute("INSERT INTO users (username, hashed_password) VALUES (?, ?)", (username, hashed_password.decode('utf-8')))
        except sqlite3.IntegrityError:
            print("Error: Username already exists.")
            conn.rollback()  # Rollback the transaction
            return False

        conn.commit()
        print(f"User '{username}' created successfully.")
        return True

    except sqlite3.Error as e:
        print(f"Database error: {e}")
        if conn:
            conn.rollback()
        return False

    finally:
        if conn:
            conn.close()


def verify_password(username, password, db_path="users.db"):
    """
    Verifies a user's password against the stored hash.

    Args:
        username (str): The username to verify.
        password (str): The password to check.
        db_path (str): The path to the SQLite database file. Defaults to "users.db".

    Returns:
        bool: True if the password is correct, False otherwise.
    """
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # Parameterized Query
        cursor.execute("SELECT hashed_password FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()

        if result:
            hashed_password = result[0].encode('utf-8')  # Convert back to bytes
            return bcrypt.checkpw(password.encode('utf-8'), hashed_password)
        else:
            print("User not found.")
            return False

    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return False

    finally:
        if conn:
            conn.close()


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
    # Example Usage
    new_username = "testuser"
    new_password = generate_strong_password()  # Generate a strong password
    print(f"Generated password for {new_username}: {new_password}")

    if create_user(new_username, new_password):
        print("User created successfully.")

        # Verify the password
        if verify_password(new_username, new_password):
            print("Password verification successful!")
        else:
            print("Password verification failed.")

        # Verify with an incorrect password
        if verify_password(new_username, "wrongpassword"):
            print("Password verification should have failed!")
        else:
            print("Password verification failed as expected.")
    else:
        print("User creation failed.")

