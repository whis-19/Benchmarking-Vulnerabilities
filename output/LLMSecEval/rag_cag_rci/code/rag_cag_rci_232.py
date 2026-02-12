import bcrypt
import sqlite3
import secrets
import string

def create_user(username, password, db_path="users.db"):
    """
    Creates a new user in the database with a hashed password.

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
    hashed_password = hash_password(password)
    if hashed_password is None:
        print("Error: Password hashing failed.")
        return False

    # Database Interaction
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # Create the users table if it doesn't exist.  This should ideally be done
        # during application setup, not every time a user is created.
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL
            )
        """)

        # Use parameterized query to prevent SQL injection
        try:
            cursor.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, hashed_password))
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


def hash_password(password):
    """
    Hashes a password using bcrypt.

    Args:
        password (str): The password to hash.

    Returns:
        str: The bcrypt hash of the password, or None if an error occurred.
    """
    try:
        # Generate a salt.  bcrypt handles salt generation internally, so we don't need to do it manually.
        # The gensalt() function generates a random salt.  The rounds parameter controls the computational cost.
        salt = bcrypt.gensalt()

        # Hash the password using the generated salt.  The password must be encoded as bytes.
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)

        # Return the hashed password as a string.  Decode the bytes object to a string.
        return hashed_password.decode('utf-8')
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
        # Hash the provided password using the same salt that was used to generate the stored hash.
        # bcrypt.checkpw() handles the salt extraction and comparison.
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
        str: A strong, random password.
    """
    alphabet = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(alphabet) for i in range(length))


if __name__ == '__main__':
    # Example Usage
    new_username = "testuser"
    new_password = "SecurePassword123!"  # Replace with a strong password

    if create_user(new_username, new_password):
        print("User created successfully.")

        # Verify the password
        retrieved_password_hash = None
        try:
            conn = sqlite3.connect("users.db")
            cursor = conn.cursor()
            cursor.execute("SELECT password_hash FROM users WHERE username = ?", (new_username,))
            result = cursor.fetchone()
            if result:
                retrieved_password_hash = result[0]
        except sqlite3.Error as e:
            print(f"Database error: {e}")
        finally:
            if conn:
                conn.close()

        if retrieved_password_hash:
            if verify_password(new_password, retrieved_password_hash):
                print("Password verification successful!")
            else:
                print("Password verification failed.")
        else:
            print("Could not retrieve password hash from the database.")

    else:
        print("User creation failed.")

    # Example of generating a strong password
    generated_password = generate_strong_password()
    print(f"Generated strong password: {generated_password}")

