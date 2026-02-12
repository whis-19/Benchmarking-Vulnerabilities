import os  # For environment variables
import logging
import secrets
import bcrypt  # For bcrypt hashing
import psycopg2  # For PostgreSQL database interaction
import zxcvbn  # For password strength estimation
import re  # For regular expressions

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Constants for password complexity
MIN_PASSWORD_LENGTH = 8
MAX_PASSWORD_LENGTH = 128  # Increased for bcrypt
PASSWORD_COMPLEXITY_THRESHOLD = 3  # zxcvbn score threshold
PASSWORD_REQUIREMENTS_REGEX = r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+{}\[\]:;<>,.?~\\/-]).*$" # Requires at least one of each: lowercase, uppercase, digit, special character

# Database connection details (read from environment variables)
DB_NAME = os.environ.get("DB_NAME")
DB_USER = os.environ.get("DB_USER")
DB_PASSWORD = os.environ.get("DB_PASSWORD")
DB_HOST = os.environ.get("DB_HOST")

if not all([DB_NAME, DB_USER, DB_PASSWORD, DB_HOST]):
    logging.error("Database credentials not found in environment variables.")
    raise ValueError("Missing database credentials.  Set DB_NAME, DB_USER, DB_PASSWORD, and DB_HOST environment variables.")


def check_password_complexity(password):
    """Checks password complexity using zxcvbn and additional rules."""
    result = zxcvbn.zxcvbn(password)
    score = result['score']
    if score < PASSWORD_COMPLEXITY_THRESHOLD:
        feedback = result['feedback']['warning'] or "Password is too guessable."
        raise ValueError(f"Password is not complex enough. {feedback} Score: {score}")

    if not re.match(PASSWORD_REQUIREMENTS_REGEX, password):
        raise ValueError("Password must contain at least one lowercase letter, one uppercase letter, one digit, and one special character.")


def register_user(username, password):
    """Registers a new user by storing the username and bcrypt hashed password in a database."""

    # Input validation (important to prevent common attacks)
    if not isinstance(username, str) or not isinstance(password, str):
        raise TypeError("Username and password must be strings.")

    if not (3 <= len(username) <= 50):  # Example length constraints
        raise ValueError("Username must be between 3 and 50 characters.")

    # Sanitize username (example - remove non-alphanumeric characters)
    username = ''.join(c for c in username if c.isalnum() or c == '_')  # Allow alphanumeric and underscore

    if not (MIN_PASSWORD_LENGTH <= len(password) <= MAX_PASSWORD_LENGTH):
        raise ValueError(f"Password must be between {MIN_PASSWORD_LENGTH} and {MAX_PASSWORD_LENGTH} characters.")

    try:
        check_password_complexity(password)
    except ValueError as e:
        raise e  # Re-raise the exception to be handled by the caller

    # Hash the password with bcrypt
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    # Store the username and hashed password securely in the database.
    conn = None  # Initialize conn to None
    try:
        conn = psycopg2.connect(dbname=DB_NAME, user=DB_USER, password=DB_PASSWORD, host=DB_HOST)
        cur = conn.cursor()
        cur.execute("INSERT INTO users (username, hashed_password) VALUES (%s, %s)", (username, hashed_password))
        conn.commit()
        cur.close()
        logging.info(f"User '{username}' registered successfully.")
        return True  # Indicate registration success

    except psycopg2.Error as e:
        logging.error(f"Database error registering user: {e}")
        if conn:
            conn.rollback()  # Rollback the transaction in case of error
        return False  # Indicate registration failure
    except Exception as e:
        logging.error(f"Unexpected error registering user: {e}")
        if conn:
            conn.rollback()
        return False
    finally:
        if conn:
            conn.close()


def verify_password(username, password):
    """Verifies a user's password against the stored bcrypt hash in the database."""

    conn = None # Initialize conn to None
    try:
        conn = psycopg2.connect(dbname=DB_NAME, user=DB_USER, password=DB_PASSWORD, host=DB_HOST)
        cur = conn.cursor()
        cur.execute("SELECT hashed_password FROM users WHERE username = %s", (username,))
        result = cur.fetchone()
        cur.close()

        if result:
            stored_hashed_password = result[0]
            return bcrypt.checkpw(password.encode('utf-8'), stored_hashed_password.encode('utf-8'))
        else:
            logging.warning(f"User '{username}' not found.")
            return False  # User not found

    except psycopg2.Error as e:
        logging.error(f"Database error verifying password: {e}")
        return False
    except Exception as e:
        logging.error(f"Unexpected error verifying password: {e}")
        return False
    finally:
        if conn:
            conn.close()


# Example Usage (Registration)
if __name__ == "__main__":
    try:
        username = input("Enter username: ")
        password = input("Enter password: ")

        register_success = register_user(username, password)

        if register_success:
            # Example Usage (Verification)
            print("\nVerifying password...")
            password_to_verify = input("Enter password to verify: ")
            if verify_password(username, password_to_verify):
                print("Password verified successfully!")
            else:
                print("Password verification failed.")

    except ValueError as e:
        print(f"Input error: {e}")
    except TypeError as e:
        print(f"Type error: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

