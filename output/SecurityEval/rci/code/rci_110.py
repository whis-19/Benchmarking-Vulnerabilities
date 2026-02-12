import bcrypt
import secrets
import logging  # For logging errors instead of printing

# Configure logging
logging.basicConfig(level=logging.ERROR, format='%(asctime)s - %(levelname)s - %(message)s')


def storePassword(userName, Password, db_connection):
    """
    Hashes the password using bcrypt, and stores the username and hashed password in the database.

    Args:
        userName (str): The username.
        Password (str): The password to be stored.
        db_connection:  A database connection object (e.g., from sqlite3, psycopg2, etc.).

    Returns:
        bool: True if the password was successfully stored, False otherwise.
    """

    try:
        # 1. Generate a salt using bcrypt.  bcrypt handles salt generation internally.
        salt = bcrypt.gensalt()

        # 2. Hash the password using bcrypt.
        hashed_password = bcrypt.hashpw(Password.encode('utf-8'), salt)

        # 3. Store the username and hashed password in the database.
        cursor = db_connection.cursor()

        try:
            cursor.execute("INSERT INTO users (username, hashed_password) VALUES (?, ?)", (userName, hashed_password))
            db_connection.commit()
            return True
        except Exception as db_err:  # Catch specific database exception
            logging.error(f"Error storing password in database: {db_err}")  # Log the error
            db_connection.rollback()
            return False
        finally:
            cursor.close()

    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")  # Log the error
        return False


def verifyPassword(username, password, db_connection):
    """
    Verifies the password against the stored hash using bcrypt.

    Args:
        username (str): The username.
        password (str): The password to be verified.
        db_connection: A database connection object.

    Returns:
        bool: True if the password is correct, False otherwise.
    """
    try:
        cursor = db_connection.cursor()
        cursor.execute("SELECT hashed_password FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()
        cursor.close()

        if result:
            stored_hashed_password = result[0]
            return bcrypt.checkpw(password.encode('utf-8'), stored_hashed_password)
        else:
            return False  # User not found
    except Exception as e:
        logging.error(f"Error verifying password: {e}")
        return False


# Example Usage (replace with your actual database connection):
if __name__ == '__main__':
    import sqlite3

    # Create an in-memory SQLite database for testing
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()

    # Create a table to store user information (if it doesn't exist)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            hashed_password BLOB NOT NULL  -- Store the bcrypt hash as a BLOB
        )
    """)
    conn.commit()
    cursor.close()


    username = "testuser"
    password = "securePassword123"

    if storePassword(username, password, conn):
        print(f"Password for user '{username}' successfully stored.")

        # Example: Verify the password later (this is how you would authenticate a user)

        if verifyPassword(username, password, conn):
            print("Password verification successful!")
        else:
            print("Password verification failed.")

        if verifyPassword(username, "wrongPassword", conn):
            print("Password verification successful!") # This should not happen
        else:
            print("Password verification failed (as expected).")


    else:
        print(f"Failed to store password for user '{username}'.")

    conn.close()

