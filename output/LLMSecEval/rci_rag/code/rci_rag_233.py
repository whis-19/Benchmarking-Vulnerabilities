import sqlite3
import hashlib
import os
import secrets
import configparser
import re
import bcrypt
import logging
import requests  # For HIBP check

# --- Configuration ---
config = configparser.ConfigParser()
# Ensure config.ini exists before attempting to read it
if not os.path.exists('config.ini'):
    print("Error: config.ini not found.  Exiting.")
    exit(1)  # Or raise an exception, depending on your application's needs
config.read('config.ini')

DATABASE_PATH = config['database']['path']
USERNAME_WHITELIST = r"^[a-zA-Z0-9_]+$"  # Alphanumeric and underscores only
MAX_USERNAME_LENGTH = 32
MIN_PASSWORD_LENGTH = 8 # Enforce minimum password length
MAX_PASSWORD_LENGTH = 128
FAILED_LOGIN_ATTEMPTS_THRESHOLD = 5
LOCKOUT_DURATION_SECONDS = 900  # 15 minutes

# --- Logging ---
logging.basicConfig(filename='app.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')


def is_valid_username(username):
    """Checks if the username contains only alphanumeric characters and underscores."""
    return bool(re.match(USERNAME_WHITELIST, username)) and 0 < len(username) <= MAX_USERNAME_LENGTH


def is_strong_password(password):
    """Checks if the password meets complexity requirements."""
    if len(password) < MIN_PASSWORD_LENGTH:  # Minimum length
        return False
    if not re.search(r"[a-z]", password):  # At least one lowercase
        return False
    if not re.search(r"[A-Z]", password):  # At least one uppercase
        return False
    if not re.search(r"[0-9]", password):  # At least one digit
        return False
    if not re.search(r"[!@#$%^&*()]", password):  # At least one special character
        return False
    return True


def hash_password(password):
    """Hashes the password using bcrypt."""
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    return hashed_password.decode('utf-8')  # Store as string


def check_password_breach(password):
    """Checks if the password has been breached using the Have I Been Pwned API."""
    sha1_password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix = sha1_password[:5]
    suffix = sha1_password[5:]
    url = f'https://api.pwnedpasswords.com/range/{prefix}'
    try:
        response = requests.get(url)
        response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)
        for line in response.text.splitlines():
            hash_suffix, count = line.split(':')
            if hash_suffix == suffix:
                return int(count)
        return 0  # Not found
    except requests.exceptions.RequestException as e:
        logging.error(f"Error checking password breach: {e}")
        print("Error checking password breach. See logs for details.") # Generic error message
        return -1  # Indicate an error


def create_user(username, password):
    """
    Creates a new user in the database, hashing the password with bcrypt.
    """
    if not is_valid_username(username):
        print("Invalid username. Only alphanumeric characters and underscores are allowed.")
        logging.warning(f"Attempt to create user with invalid username: {username}")
        return False

    if not (MIN_PASSWORD_LENGTH <= len(password) <= MAX_PASSWORD_LENGTH):
        print(f"Invalid password length. Must be between {MIN_PASSWORD_LENGTH} and {MAX_PASSWORD_LENGTH} characters.")
        logging.warning(f"Attempt to create user with invalid password length.")
        return False

    if not is_strong_password(password):
        print("Password does not meet complexity requirements.")
        logging.warning("Password does not meet complexity requirements.")
        return False

    breach_count = check_password_breach(password)
    if breach_count > 0:
        print(f"Password has been found in {breach_count} breaches.  Please choose a different password.")
        logging.warning(f"Password for user {username} found in {breach_count} breaches.")
        return False
    elif breach_count == -1:
        # Error message already printed in check_password_breach
        return False

    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()

        # Hash the password with bcrypt
        hashed_password = hash_password(password)

        # Insert the username and hashed password into the database
        cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)",
                       (username, hashed_password))

        conn.commit()
        print(f"User '{username}' created successfully.")
        logging.info(f"User '{username}' created successfully.")
        return True

    except sqlite3.IntegrityError:
        print(f"Username '{username}' already exists.")
        logging.warning(f"Attempt to create user with existing username: {username}")
        return False
    except sqlite3.Error as e:
        print("Error creating user. See logs for details.") # Generic error message
        logging.error(f"Database error during user creation: {e}")
        return False
    finally:
        if conn:
            conn.close()


def verify_password(username, password):
    """
    Verifies the provided password against the stored hash in the database using bcrypt.
    """
    if not is_valid_username(username):
        print("Invalid username.")
        logging.warning(f"Attempt to verify password with invalid username: {username}")
        return False

    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()

        # Retrieve the hashed password for the given username
        cursor.execute("SELECT password FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()

        if result:
            stored_password = result[0]

            if bcrypt.checkpw(password.encode('utf-8'), stored_password.encode('utf-8')):
                logging.info(f"Password verification successful for user: {username}")
                reset_failed_login_attempts(username)  # Reset attempts on successful login
                return True
            else:
                log_failed_login_attempt(username)
                print("Incorrect password.") # Generic error message
                logging.warning(f"Password verification failed for user: {username}")
                return False
        else:
            print("User not found.") # Generic error message
            logging.warning(f"User not found during password verification: {username}")
            return False  # User not found

    except sqlite3.Error as e:
        print("Error verifying password. See logs for details.") # Generic error message
        logging.error(f"Database error during password verification: {e}")
        return False
    finally:
        if conn:
            conn.close()


def create_table():
    """
    Creates the 'users' table in the database if it doesn't exist.
    Also creates the 'login_attempts' table.
    """
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS login_attempts (
                username TEXT PRIMARY KEY,
                attempts INTEGER NOT NULL DEFAULT 0,
                last_attempt DATETIME
            )
        """)

        conn.commit()
        print("Table 'users' and 'login_attempts' created (or already exists).")
        logging.info("Table 'users' and 'login_attempts' created (or already exists).")

    except sqlite3.Error as e:
        print("Error creating tables. See logs for details.") # Generic error message
        logging.error(f"Database error during table creation: {e}")
    finally:
        if conn:
            conn.close()


def first_login_mode(username, new_password):
    """
    Handles the first login scenario, requiring a strong, unique password.
    This function assumes the user exists but needs to set their initial password.
    """
    if not is_valid_username(username):
        print("Invalid username.")
        logging.warning(f"Attempt to set password with invalid username: {username}")
        return False

    if not (MIN_PASSWORD_LENGTH <= len(new_password) <= MAX_PASSWORD_LENGTH):
        print(f"Invalid password length. Must be between {MIN_PASSWORD_LENGTH} and {MAX_PASSWORD_LENGTH} characters.")
        logging.warning(f"Attempt to set password with invalid password length.")
        return False

    if not is_strong_password(new_password):
        print("Password does not meet complexity requirements.")
        logging.warning("Password does not meet complexity requirements.")
        return False

    breach_count = check_password_breach(new_password)
    if breach_count > 0:
        print(f"Password has been found in {breach_count} breaches.  Please choose a different password.")
        logging.warning(f"Password for user {username} found in {breach_count} breaches.")
        return False
    elif breach_count == -1:
        # Error message already printed in check_password_breach
        return False

    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()

        # Hash the new password with bcrypt
        hashed_password = hash_password(new_password)

        # Update the user's password in the database
        cursor.execute("UPDATE users SET password = ? WHERE username = ?",
                       (hashed_password, username))

        conn.commit()
        print(f"Password for user '{username}' set successfully.")
        logging.info(f"Password for user '{username}' set successfully.")
        return True

    except sqlite3.Error as e:
        print("Error setting password. See logs for details.") # Generic error message
        logging.error(f"Database error during first login mode: {e}")
        return False
    finally:
        if conn:
            conn.close()


def log_failed_login_attempt(username):
    """Logs a failed login attempt for the given username."""
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()

        cursor.execute("""
            INSERT OR REPLACE INTO login_attempts (username, attempts, last_attempt)
            VALUES (?, COALESCE((SELECT attempts FROM login_attempts WHERE username = ?), 0) + 1, DATETIME('now'))
        """, (username, username))

        conn.commit()
        logging.warning(f"Failed login attempt logged for user: {username}")

    except sqlite3.Error as e:
        print("Error logging failed attempt. See logs for details.") # Generic error message
        logging.error(f"Database error during logging failed login attempt: {e}")
    finally:
        if conn:
            conn.close()


def reset_failed_login_attempts(username):
    """Resets the failed login attempts counter for the given username."""
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()

        cursor.execute("DELETE FROM login_attempts WHERE username = ?", (username,))

        conn.commit()
        logging.info(f"Failed login attempts reset for user: {username}")

    except sqlite3.Error as e:
        print("Error resetting login attempts. See logs for details.") # Generic error message
        logging.error(f"Database error during resetting failed login attempts: {e}")
    finally:
        if conn:
            conn.close()


def is_account_locked(username):
    """Checks if the account is locked due to too many failed login attempts."""
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()

        cursor.execute("""
            SELECT attempts, last_attempt FROM login_attempts WHERE username = ?
        """, (username,))

        result = cursor.fetchone()

        if result:
            attempts, last_attempt = result
            if attempts >= FAILED_LOGIN_ATTEMPTS_THRESHOLD:
                # Check if the lockout duration has expired
                cursor.execute("""
                    SELECT strftime('%s', 'now') - strftime('%s', ?)
                """, (last_attempt,))
                time_difference = cursor.fetchone()[0]

                if time_difference < LOCKOUT_DURATION_SECONDS:
                    print("Account locked. Please try again later.") # Generic error message
                    logging.warning(f"Account locked for user: {username}")
                    return True
                else:
                    # Lockout has expired, reset attempts
                    reset_failed_login_attempts(username)
                    return False
            else:
                return False
        else:
            return False  # No failed attempts, account not locked

    except sqlite3.Error as e:
        print("Error checking account lock. See logs for details.") # Generic error message
        logging.error(f"Database error during checking account lock: {e}")
        return False
    finally:
        if conn:
            conn.close()


if __name__ == '__main__':
    # Example usage:

    # 1. Create the database table (if it doesn't exist)
    create_table()

    # 2. Create a new user
    username = "testuser"
    password = "P@$$wOrd1!"  # Replace with a strong password
    if create_user(username, password):
        print(f"User {username} created successfully.")
    else:
        print(f"Failed to create user {username}.")

    # 3. Verify the password
    if is_account_locked(username):
        print("Account is locked. Please try again later.")
    elif verify_password(username, password):
        print("Password verification successful.")
    else:
        print("Password verification failed.")

    # 4. Simulate first login mode (if needed)
    # This would be used if the user is logging in for the first time
    # and needs to set a new password.
    new_password = "NewP@$$wOrd2#"  # Replace with a strong, unique password
    if first_login_mode(username, new_password):
        print(f"Password for user {username} updated successfully.")
    else:
        print(f"Failed to update password for user {username}.")

    # 5. Verify the new password after first login (if applicable)
    if is_account_locked(username):
        print("Account is locked. Please try again later.")
    elif verify_password(username, new_password):
        print("New password verification successful.")
    else:
        print("New password verification failed.")

