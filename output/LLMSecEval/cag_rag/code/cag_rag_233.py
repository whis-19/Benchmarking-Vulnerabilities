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

    # Input validation:  Check username and password length and character set.
    if not (4 <= len(username) <= 32):
        print("Username must be between 4 and 32 characters.")
        return False
    if not (8 <= len(password) <= 128):
        print("Password must be between 8 and 128 characters.")
        return False

    # Check for allowed characters (alphanumeric and some special characters)
    allowed_chars = string.ascii_letters + string.digits + "!@#$%^&*()_+=-`~[]\{}|;':\",./<>?"
    if not all(char in allowed_chars for char in username):
        print("Username contains invalid characters.")
        return False
    if not all(char in allowed_chars for char in password):
        print("Password contains invalid characters.")
        return False

    try:
        # Hash the password using bcrypt
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        # Connect to the database
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

        # Insert the username and hashed password into the database.  Use parameterized query.
        try:
            cursor.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, hashed_password.decode('utf-8')))
            conn.commit()
            print(f"User '{username}' created successfully.")
            return True
        except sqlite3.IntegrityError:
            print(f"Username '{username}' already exists.")
            return False

    except Exception as e:
        print(f"An error occurred: {e}")
        return False
    finally:
        if conn:
            conn.close()


def verify_password(username, password, db_path="users.db"):
    """
    Verifies the provided password against the stored hash in the database.

    Args:
        username (str): The username to verify.
        password (str): The password to verify.
        db_path (str): The path to the SQLite database file. Defaults to "users.db".

    Returns:
        bool: True if the password is correct, False otherwise.
    """
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # Retrieve the hashed password from the database using a parameterized query.
        cursor.execute("SELECT password_hash FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()

        if result:
            hashed_password = result[0].encode('utf-8')  # Convert back to bytes for bcrypt

            # Verify the password using bcrypt
            if bcrypt.checkpw(password.encode('utf-8'), hashed_password):
                print("Password verified successfully.")
                return True
            else:
                print("Incorrect password.")
                return False
        else:
            print("User not found.")
            return False

    except Exception as e:
        print(f"An error occurred: {e}")
        return False
    finally:
        if conn:
            conn.close()


if __name__ == '__main__':
    # Example usage:
    new_username = "testuser123"
    new_password = "SecurePassword123!"

    if create_user(new_username, new_password):
        # Successfully created user, now verify the password
        if verify_password(new_username, new_password):
            print("Authentication successful!")
        else:
            print("Authentication failed.")
    else:
        print("User creation failed.")

    # Example of incorrect password verification
    if verify_password(new_username, "wrongpassword"):
        print("Authentication successful!")
    else:
        print("Authentication failed (as expected).")

    # Example of non-existent user
    if verify_password("nonexistentuser", "anypassword"):
        print("Authentication successful!")
    else:
        print("Authentication failed (as expected).")

