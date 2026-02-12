import sqlite3
import bcrypt
import secrets
import re  # For email validation

# Database setup (consider using a more robust database like PostgreSQL for production)
DATABASE_FILE = 'users.db'

def create_table():
    """Creates the users table if it doesn't exist."""
    conn = None
    try:
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash BLOB NOT NULL,
                first_name TEXT,
                last_name TEXT,
                email TEXT
            )
        ''')
        conn.commit()
    except sqlite3.Error as e:
        print(f"Database error: {e}")
    finally:
        if conn:
            conn.close()


def hash_password(password):
    """Hashes the password using bcrypt."""
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    return hashed_password


def is_valid_email(email):
    """Validates the email address format using a regular expression."""
    email_regex = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    return re.match(email_regex, email) is not None


def is_valid_username(username):
    """Validates the username format (alphanumeric and underscores only)."""
    username_regex = r"^[a-zA-Z0-9_]+$"
    return re.match(username_regex, username) is not None


def is_strong_password(password):
    """Checks if the password meets complexity requirements."""
    # Minimum 8 characters, at least one uppercase, one lowercase, one number, and one special character
    password_regex = r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+{}\[\]:;<>,.?~\\/-]).{8,}$"
    return re.match(password_regex, password) is not None


def register_user(username, password, first_name, last_name, email):
    """Registers a new user in the database with input validation."""
    conn = None
    try:
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()

        # Input Validation
        if not is_valid_username(username):
            return "Invalid username.  Must contain only alphanumeric characters and underscores."

        if len(username) > 50:  # Example length restriction
            return "Username too long. Maximum 50 characters."

        if not is_strong_password(password):
            return "Password does not meet complexity requirements. Minimum 8 characters, one uppercase, one lowercase, one number, and one special character."

        if len(password) > 100:  # Example length restriction
            return "Password too long. Maximum 100 characters."

        if not is_valid_email(email):
            return "Invalid email address."

        if len(first_name) > 100 or len(last_name) > 100:
            return "First name or last name too long. Maximum 100 characters."


        # Hash password
        password_hash = hash_password(password)

        # Insert user data into the database
        try:
            cursor.execute('''
                INSERT INTO users (username, password_hash, first_name, last_name, email)
                VALUES (?, ?, ?, ?, ?)
            ''', (username, password_hash, first_name, last_name, email))

            conn.commit()
            return "Registration successful!"
        except sqlite3.IntegrityError:
            return "Username already exists."  # Handle duplicate username

    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return "Registration failed. Please try again later."  # Generic error message
    finally:
        if conn:
            conn.close()


# Example usage (replace with your web framework's input handling)
if __name__ == '__main__':
    # Create the table if it doesn't exist
    create_table()

    # Simulate user input (replace with actual form data)
    username = input("Enter username: ")
    password = input("Enter password: ")
    first_name = input("Enter first name: ")
    last_name = input("Enter last name: ")
    email = input("Enter email: ")

    # Register the user
    registration_result = register_user(username, password, first_name, last_name, email)
    print(registration_result)

