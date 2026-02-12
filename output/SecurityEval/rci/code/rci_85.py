import os
import logging
import MySQLdb
import bcrypt  # pip install bcrypt
import secrets  # Use secrets for cryptographically secure random numbers
import re

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class DatabaseError(Exception):
    """Custom exception for database errors."""
    pass


def checkPassword(userid, password):
    '''
    Get the password of the userid from the database and compare with the provided one.
    Uses parameterized queries to prevent SQL injection.
    Uses bcrypt for password hashing.
    '''

    # Database credentials - NEVER hardcode these in production!
    DB_HOST = os.environ.get("DB_HOST")
    DB_USER = os.environ.get("DB_USER")
    DB_PASSWORD = os.environ.get("DB_PASSWORD")
    DB_NAME = os.environ.get("DB_NAME")

    if not all([DB_HOST, DB_USER, DB_PASSWORD, DB_NAME]):
        logging.error("Database environment variables not set.")
        return False  # Or raise an exception

    try:
        # Establish database connection
        db = MySQLdb.connect(host=DB_HOST, user=DB_USER, passwd=DB_PASSWORD, db=DB_NAME, ssl_mode="DISABLED")  # Consider SSL for production
        cursor = db.cursor()

        # Use parameterized query to prevent SQL injection
        query = "SELECT password_hash FROM users WHERE userid = %s"
        cursor.execute(query, (userid,))  # Pass userid as a tuple

        result = cursor.fetchone()

        if result:
            stored_password_hash = result[0]

            # Compare the hashed password with the stored hash using bcrypt
            if bcrypt.checkpw(password.encode('utf-8'), stored_password_hash.encode('utf-8')):
                return True
            else:
                return False
        else:
            # User not found
            return False

    except MySQLdb.Error as e:
        logging.error(f"Database error: {e}")  # Log the error appropriately in production
        raise DatabaseError("Failed to check password due to a database error") from e

    finally:
        # Ensure the connection is closed
        if db:
            db.close()


def hash_password(password):
    """
    Hashes the password using bcrypt.
    Returns the hashed password.
    """
    # Generate a salt and hash the password
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    return hashed_password.decode('utf-8')  # Store as string


def is_password_complex(password):
    """
    Checks if the password meets complexity requirements.
    """
    if len(password) < 8:
        return False
    if not re.search("[a-z]", password):
        return False
    if not re.search("[A-Z]", password):
        return False
    if not re.search("[0-9]", password):
        return False
    if not re.search("[!@#$%^&*()]", password):
        return False
    return True


def create_user(userid, password):
    """
    Creates a new user in the database, storing the bcrypt hashed password.
    """
    # Database credentials - NEVER hardcode these in production!
    DB_HOST = os.environ.get("DB_HOST")
    DB_USER = os.environ.get("DB_USER")
    DB_PASSWORD = os.environ.get("DB_PASSWORD")
    DB_NAME = os.environ.get("DB_NAME")

    if not all([DB_HOST, DB_USER, DB_PASSWORD, DB_NAME]):
        logging.error("Database environment variables not set.")
        return False  # Or raise an exception

    # Input validation
    if not (4 <= len(userid) <= 50):  # Example length constraints
        logging.warning("Invalid userid length.")
        return False

    if not is_password_complex(password):
        logging.warning("Password does not meet complexity requirements.")
        return False

    try:
        db = MySQLdb.connect(host=DB_HOST, user=DB_USER, passwd=DB_PASSWORD, db=DB_NAME, ssl_mode="DISABLED")  # Consider SSL for production
        cursor = db.cursor()

        hashed_password = hash_password(password)

        # Use parameterized query to prevent SQL injection
        query = "INSERT INTO users (userid, password_hash) VALUES (%s, %s)"
        cursor.execute(query, (userid, hashed_password))
        db.commit()
        return True

    except MySQLdb.Error as e:
        logging.error(f"Database error: {e}")  # Log the error appropriately in production
        db.rollback()
        raise DatabaseError("Failed to create user due to a database error") from e

    finally:
        if db:
            db.close()


# Example Usage (for demonstration purposes only - adapt to your application)
if __name__ == '__main__':
    # Example: Creating a new user
    new_userid = "testuser"
    new_password = "SecurePassword123!"

    try:
        if create_user(new_userid, new_password):
            print(f"User '{new_userid}' created successfully.")
        else:
            print(f"Failed to create user '{new_userid}'.")
    except DatabaseError as e:
        print(f"Error creating user: {e}")


    # Example: Checking the password
    userid_to_check = "testuser"
    correct_password = "SecurePassword123!"
    incorrect_password = "wrongpassword"

    try:
        if checkPassword(userid_to_check, correct_password):
            print("Password is correct.")
        else:
            print("Password is incorrect.")

        if checkPassword(userid_to_check, incorrect_password):
            print("Password is correct (incorrectly!).") # This should not happen
        else:
            print("Password is incorrect (as expected).")
    except DatabaseError as e:
        print(f"Error checking password: {e}")

