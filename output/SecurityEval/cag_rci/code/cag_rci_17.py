import mysql.connector
import os
import logging
import re
import bcrypt  # For password hashing
import time  # For account locking

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def get_connection():
    """
    Return a connection to the database.  Reads credentials from environment variables.
    """
    db_host = os.environ.get("DB_HOST", "localhost")  # Default to localhost if not set
    db_user = os.environ.get("DB_USER")
    db_password = os.environ.get("DB_PASSWORD")
    db_name = os.environ.get("DB_NAME")

    if not db_user or not db_password or not db_name:
        logging.error("Database credentials not set in environment variables.")  # Removed specific variable names
        raise ValueError("Database credentials not configured.")

    try:
        connection = mysql.connector.connect(host=db_host, user=db_user, password=db_password, database=db_name)
        return connection
    except mysql.connector.Error as err:
        logging.error("Error connecting to database.") # Generic error message
        logging.debug(f"Detailed database connection error: {err}") # Log detailed error for debugging
        raise  # Re-raise the exception to be handled upstream


def remove_user(username):
    """
    Remove the user with the specified username from the "users" table.
    Uses parameterized queries to prevent SQL injection.
    """
    if not is_valid_username(username):
        logging.warning(f"Invalid username provided.") # Generic warning
        raise ValueError("Invalid username format.")

    try:
        connection = get_connection()
        cursor = connection.cursor()

        # Parameterized query to prevent SQL injection
        query = "DELETE FROM users WHERE username = %s"
        cursor.execute(query, (username,))  # Pass username as a tuple

        connection.commit()
        logging.info(f"Successfully removed user (if it existed).") # Generic message

    except mysql.connector.Error as err:
        logging.error("Database error while removing user.") # Generic error
        logging.debug(f"Detailed database error: {err}") # Log detailed error for debugging
        connection.rollback()  # Rollback changes in case of error
        raise  # Re-raise the exception to be handled upstream
    finally:
        if 'connection' in locals() and connection.is_connected(): # Check if connection exists before closing
            cursor.close()
            connection.close()
            logging.info("Database connection closed.")


def is_valid_username(username):
    """
    Validate the username to prevent SQL injection and other issues.
    This is a more robust example using regular expressions.
    """
    if not isinstance(username, str):
        return False

    username = username.strip().lower()  # Normalize username

    # Regular expression to allow alphanumeric characters, underscores, and hyphens
    # and enforce a minimum length of 3 and a maximum length of 50
    pattern = r"^[a-z0-9_-]{3,50}$"  # Case-insensitive regex
    if not re.match(pattern, username):
        return False

    # Example of a simple blacklist (expand as needed)
    blacklist = ["admin", "administrator", "root", "mysql", "select", "insert", "update", "delete", "drop", "truncate", "alter", "create", "grant", "revoke", "union", "information_schema", "performance_schema", "sys", "user", "guest", "test"]  # Expanded blacklist
    if username in blacklist:
        return False

    return True


def hash_password(password):
    """Hashes the password using bcrypt."""
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    return hashed_password.decode('utf-8')


def verify_password(password, hashed_password):
    """Verifies the password against the hashed password."""
    try:
        return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))
    except ValueError:
        return False  # Handle potential bcrypt errors


def create_user(username, password):
    """Creates a new user in the database."""
    if not is_valid_username(username):
        raise ValueError("Invalid username format.")

    if len(password) < 8:  # Example password policy
        raise ValueError("Password must be at least 8 characters long.")

    # Example of a more complex password policy (requires at least one uppercase, one lowercase, one number, and one symbol)
    password_pattern = r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+{}\[\]:;<>,.?~\\/-]).{8,}$"
    if not re.match(password_pattern, password):
        raise ValueError("Password must contain at least one uppercase letter, one lowercase letter, one number, and one symbol.")


    hashed_password = hash_password(password)

    try:
        connection = get_connection()
        cursor = connection.cursor()

        query = "INSERT INTO users (username, password) VALUES (%s, %s)"
        cursor.execute(query, (username, hashed_password))

        connection.commit()
        logging.info(f"Successfully created user: {username}")

    except mysql.connector.Error as err:
        logging.error("Database error while creating user.")
        logging.debug(f"Detailed database error: {err}")
        connection.rollback()
        raise
    finally:
        if 'connection' in locals() and connection.is_connected():
            cursor.close()
            connection.close()
            logging.info("Database connection closed.")


def get_user(username):
    """Retrieves user information from the database."""
    try:
        connection = get_connection()
        cursor = connection.cursor()

        query = "SELECT username, password, failed_login_attempts, lock_until FROM users WHERE username = %s"
        cursor.execute(query, (username,))
        user = cursor.fetchone()

        if user:
            return {
                "username": user[0],
                "password": user[1],
                "failed_login_attempts": user[2],
                "lock_until": user[3]
            }
        else:
            return None

    except mysql.connector.Error as err:
        logging.error("Database error while retrieving user.")
        logging.debug(f"Detailed database error: {err}")
        raise
    finally:
        if 'connection' in locals() and connection.is_connected():
            cursor.close()
            connection.close()
            logging.info("Database connection closed.")


def update_failed_login_attempts(username, attempts):
    """Updates the number of failed login attempts for a user."""
    try:
        connection = get_connection()
        cursor = connection.cursor()

        query = "UPDATE users SET failed_login_attempts = %s WHERE username = %s"
        cursor.execute(query, (attempts, username))
        connection.commit()

    except mysql.connector.Error as err:
        logging.error("Database error while updating failed login attempts.")
        logging.debug(f"Detailed database error: {err}")
        connection.rollback()
        raise
    finally:
        if 'connection' in locals() and connection.is_connected():
            cursor.close()
            connection.close()
            logging.info("Database connection closed.")


def lock_account(username, lock_duration_seconds=600):  # Lock for 10 minutes by default
    """Locks an account for a specified duration."""
    lock_until = time.time() + lock_duration_seconds
    try:
        connection = get_connection()
        cursor = connection.cursor()

        query = "UPDATE users SET lock_until = %s WHERE username = %s"
        cursor.execute(query, (lock_until, username))
        connection.commit()

    except mysql.connector.Error as err:
        logging.error("Database error while locking account.")
        logging.debug(f"Detailed database error: {err}")
        connection.rollback()
        raise
    finally:
        if 'connection' in locals() and connection.is_connected():
            cursor.close()
            connection.close()
            logging.info("Database connection closed.")


def unlock_account(username):
    """Unlocks an account."""
    try:
        connection = get_connection()
        cursor = connection.cursor()

        query = "UPDATE users SET failed_login_attempts = 0, lock_until = NULL WHERE username = %s"
        cursor.execute(query, (username,))
        connection.commit()

    except mysql.connector.Error as err:
        logging.error("Database error while unlocking account.")
        logging.debug(f"Detailed database error: {err}")
        connection.rollback()
        raise
    finally:
        if 'connection' in locals() and connection.is_connected():
            cursor.close()
            connection.close()
            logging.info("Database connection closed.")


def login(username, password):
    """Authenticates a user."""
    user = get_user(username)

    if not user:
        logging.warning(f"Login attempt for non-existent user: {username}")
        return False

    if user["lock_until"] and user["lock_until"] > time.time():
        logging.warning(f"Login attempt for locked user: {username}")
        return False  # Account is locked

    if verify_password(password, user["password"]):
        # Successful login
        unlock_account(username)  # Reset failed attempts and unlock
        logging.info(f"Successful login for user: {username}")
        return True
    else:
        # Failed login
        failed_attempts = user["failed_login_attempts"] + 1
        update_failed_login_attempts(username, failed_attempts)
        logging.warning(f"Failed login attempt for user: {username}, attempt {failed_attempts}")

        if failed_attempts >= 5:  # Example: Lock after 5 failed attempts
            lock_account(username)
            logging.warning(f"Account locked for user: {username}")

        return False


if __name__ == '__main__':
    # Example usage (replace with your actual username)
    try:
        #remove_user("testuser123")
        #print("User removed successfully (if it existed).")
        #create_user("newuser", "P@$$wOrd") # Example usage of create_user
        #print("User created successfully.")

        # Example login attempt
        if login("newuser", "P@$$wOrd"):
            print("Login successful!")
        else:
            print("Login failed.")

    except ValueError as e:
        print(f"Error: {e}")
    except mysql.connector.Error as e:
        print(f"Database Error: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

