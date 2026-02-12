import sqlite3
import bcrypt  # pip install bcrypt
import os
import configparser
import secrets
import time
from itsdangerous import URLSafeTimedSerializer

# Configuration
config = configparser.ConfigParser()
config.read('config.ini')

DATABASE_PATH = config['database']['path']
SECRET_KEY = config['security']['secret_key']
LOGIN_ATTEMPTS = int(config['security']['login_attempts'])  # Read from config
LOCKOUT_TIME = int(config['security']['lockout_time'])  # Read from config
PASSWORD_RESET_EXPIRATION = int(config['security']['password_reset_expiration']) # Read from config
SALT_LENGTH = int(config['security']['salt_length']) # Read from config
MIN_PASSWORD_LENGTH = int(config['security']['min_password_length']) # Read from config

# Initialize the serializer for password reset tokens
ts = URLSafeTimedSerializer(SECRET_KEY)


def create_database():
    """Creates the database and user table if they don't exist."""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            first_login BOOLEAN NOT NULL DEFAULT TRUE,
            failed_attempts INTEGER NOT NULL DEFAULT 0,
            lockout_until REAL
        )
    """)
    conn.commit()
    conn.close()


def hash_password(password):
    """Hashes the password using bcrypt."""
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(rounds=12)) # Explicitly set rounds
    return hashed_password.decode('utf-8')  # Store as string


def create_user(username, password):
    """Creates a new user account."""
    create_database()

    if not is_password_complex(password):
        print(f"Password does not meet complexity requirements. Minimum length: {MIN_PASSWORD_LENGTH}")
        return False

    password_hash = hash_password(password)

    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        cursor.execute("INSERT INTO users (username, password_hash, first_login) VALUES (?, ?, ?)",
                       (username, password_hash, True))
        conn.commit()
        conn.close()
        return True
    except sqlite3.IntegrityError:
        print("Username already exists.")
        return False
    except Exception as e:
        print(f"Error creating user: {e}")
        return False


def verify_password(username, password):
    """Verifies the password against the stored hash."""
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT password_hash, failed_attempts, lockout_until FROM users WHERE username = ?",
                       (username,))
        result = cursor.fetchone()
        conn.close()

        if result:
            stored_password_hash, failed_attempts, lockout_until = result

            if lockout_until and time.time() < lockout_until:
                print("Account is locked. Please try again later.")
                return False

            if bcrypt.checkpw(password.encode('utf-8'), stored_password_hash.encode('utf-8')):
                reset_failed_attempts(username)
                return True
            else:
                increment_failed_attempts(username)
                print("Login failed.")
                return False
        else:
            print("User not found.")
            return False
    except Exception as e:
        print(f"Error verifying password: {e}")
        return False


def increment_failed_attempts(username):
    """Increments the failed login attempts for a user."""
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET failed_attempts = failed_attempts + 1 WHERE username = ?", (username,))
        conn.commit()

        cursor.execute("SELECT failed_attempts FROM users WHERE username = ?", (username,))
        attempts = cursor.fetchone()[0]

        if attempts >= LOGIN_ATTEMPTS:
            lock_account(username)

        conn.close()
    except Exception as e:
        print(f"Error incrementing failed attempts: {e}")


def reset_failed_attempts(username):
    """Resets the failed login attempts for a user."""
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET failed_attempts = 0, lockout_until = NULL WHERE username = ?", (username,))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Error resetting failed attempts: {e}")


def lock_account(username):
    """Locks an account for a specified time."""
    try:
        lockout_time = time.time() + LOCKOUT_TIME
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET lockout_until = ? WHERE username = ?", (lockout_time, username,))
        conn.commit()
        conn.close()
        print(f"Account {username} locked for {LOCKOUT_TIME // 60} minutes.")
    except Exception as e:
        print(f"Error locking account: {e}")


def first_login_mode(username):
    """Simulates a first login mode where the user must set a new password."""
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT first_login FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()

        if not result or not result[0]:
            print("Not first login.")
            return False

        print("First login detected. Please set a new strong password.")
        new_password = input("Enter new password: ")
        if not new_password:
            print("Password cannot be empty.")
            return False

        if not is_password_complex(new_password):
            print(f"Password does not meet complexity requirements. Minimum length: {MIN_PASSWORD_LENGTH}")
            return False

        password_hash = hash_password(new_password)

        cursor.execute("UPDATE users SET password_hash = ?, first_login = ? WHERE username = ?",
                       (password_hash, False, username))
        conn.commit()
        conn.close()
        print("Password updated successfully.")
        return True

    except Exception as e:
        print(f"Error updating password: {e}")
        return False


def generate_password_reset_token(username):
    """Generates a password reset token for the given username."""
    return ts.dumps(username, salt='password-reset-salt')


def verify_password_reset_token(token, expiration=None):  # Token valid for 1 hour
    """Verifies the password reset token and returns the username."""
    if expiration is None:
        expiration = PASSWORD_RESET_EXPIRATION
    try:
        username = ts.loads(token, salt='password-reset-salt', max_age=expiration)
        return username
    except Exception as e:
        print(f"Invalid or expired token: {e}")
        return None


def reset_password(username, new_password, token):
    """Resets the password for the given username."""

    if not is_password_complex(new_password):
        print(f"Password does not meet complexity requirements. Minimum length: {MIN_PASSWORD_LENGTH}")
        return False

    password_hash = hash_password(new_password)

    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET password_hash = ?, failed_attempts = 0, lockout_until = NULL WHERE username = ?",
                       (password_hash, username))
        conn.commit()
        conn.close()
        print("Password reset successfully.")
        invalidate_password_reset_token(token) # Invalidate the token
        return True
    except Exception as e:
        print(f"Error resetting password: {e}")
        return False

def invalidate_password_reset_token(token):
    """
    This is a placeholder for invalidating the token.  In a real application,
    you would store used tokens in a separate table in the database and check
    against that table before allowing a password reset.  This prevents token reuse.
    """
    print("Token invalidation not implemented.  This is a critical security step.")
    # In a real implementation, you would:
    # 1. Create a table to store used tokens (token, username, timestamp).
    # 2. Insert the used token into the table.
    # 3. Before resetting the password, check if the token exists in the table.
    #    If it does, the token has already been used and the reset should be rejected.
    pass


def sanitize_input(input_string):
    """Sanitizes user input to prevent XSS and other attacks."""
    # This is a basic example; adapt to your specific needs
    return input_string.replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;").replace("'", "&#x27;")


def is_password_complex(password):
    """Checks if the password meets complexity requirements."""
    if len(password) < MIN_PASSWORD_LENGTH:
        return False
    # Add more checks here (e.g., uppercase, lowercase, numbers, symbols)
    return True


# Example Usage (Registration and Login)
if __name__ == "__main__":
    # Create a config.ini file (outside the source code directory)
    # with the following structure:
    # [database]
    # path = users.db
    # [security]
    # secret_key = your_secret_key  # Change this to a strong, random key!
    # login_attempts = 5
    # lockout_time = 900
    # password_reset_expiration = 3600
    # salt_length = 16
    # min_password_length = 8
    #
    # IMPORTANT: Ensure that the config.ini file has restrictive permissions
    # (e.g., 600 or 400) so that only the user running the application can read it.

    username = input("Enter username: ")
    username = sanitize_input(username)  # Sanitize username

    password = input("Enter password: ")

    if create_user(username, password):
        print("User created successfully.")

        # Simulate login
        login_username = input("Enter username to login: ")
        login_username = sanitize_input(login_username)  # Sanitize login username
        login_password = input("Enter password to login: ")

        if verify_password(login_username, login_password):
            print("Login successful!")
            if first_login_mode(login_username):
                print("First login completed.")
        else:
            print("Login failed.")

        # Simulate password reset
        reset_token = generate_password_reset_token(username)
        print(f"Password reset token: {reset_token}")

        # Simulate user clicking the reset link and entering a new password
        token_username = verify_password_reset_token(reset_token)
        if token_username:
            new_password = input("Enter new password: ")
            if reset_password(token_username, new_password, reset_token):
                print("Password reset successfully.")
            else:
                print("Password reset failed.")
        else:
            print("Invalid token")
    else:
        print("User creation failed.")

