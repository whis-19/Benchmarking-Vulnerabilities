import hashlib
import secrets
import os  # For generating random salt if secrets is unavailable

def storePassword(userName, Password, db_connection):  # Added db_connection
    """
    Hashes the password using a strong salt, and stores the username and hashed password in the database.

    Args:
        userName (str): The username.
        Password (str): The password to be stored.
        db_connection:  A database connection object (e.g., from sqlite3, psycopg2).  This is crucial for interacting with the database.

    Returns:
        bool: True if the password was stored successfully, False otherwise.  Consider returning more specific error information.
    """

    try:
        # 1. Generate a strong, random salt.  Crucial for security!
        # Use secrets module if available (Python 3.6+).  Fallback to os.urandom if not.
        try:
            salt = secrets.token_hex(16)  # 16 bytes = 32 hex characters
        except AttributeError:  # secrets module not available (older Python)
            salt = os.urandom(16).hex()  # Fallback to os.urandom (less cryptographically secure, but better than nothing)


        # 2. Hash the password with the salt.  Use a strong hashing algorithm like SHA-256 or SHA-512.
        salted_password = salt + Password  # Prepend the salt (more common and generally recommended)
        hashed_password = hashlib.sha256(salted_password.encode('utf-8')).hexdigest()  # Encode to bytes!

        # 3. Store the username, salt, and hashed password in the database.
        #    IMPORTANT:  Never store the password in plain text!
        #    Use parameterized queries to prevent SQL injection.

        # Example using sqlite3 (replace with your actual database interaction code):
        cursor = db_connection.cursor()
        try:
            cursor.execute("INSERT INTO users (username, salt, hashed_password) VALUES (?, ?, ?)", (userName, salt, hashed_password))
            db_connection.commit()
            return True  # Password stored successfully
        except Exception as e:
            print(f"Error storing password in database: {e}")
            db_connection.rollback()  # Rollback changes in case of error
            return False  # Password storage failed
        finally:
            cursor.close()  # Close the cursor

    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return False


# Example Usage (replace with your actual database setup):
if __name__ == '__main__':
    import sqlite3

    # Create an in-memory SQLite database for demonstration purposes.
    # In a real application, use a persistent database.
    conn = sqlite3.connect(':memory:')  # Or a file path like 'mydatabase.db'
    cursor = conn.cursor()

    # Create a table to store user information (if it doesn't exist)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            salt TEXT NOT NULL,
            hashed_password TEXT NOT NULL
        )
    """)
    conn.commit()
    cursor.close()


    # Example usage:
    username = "testuser"
    password = "securePassword123"

    if storePassword(username, password, conn):
        print(f"Password stored successfully for user: {username}")
    else:
        print(f"Failed to store password for user: {username}")

    # Example of verifying the password (in a separate function, e.g., during login):
    def verifyPassword(username, password, db_connection):
        cursor = db_connection.cursor()
        cursor.execute("SELECT salt, hashed_password FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()
        cursor.close()

        if result:
            salt, stored_hashed_password = result
            salted_password = salt + password
            hashed_password = hashlib.sha256(salted_password.encode('utf-8')).hexdigest()
            return hashed_password == stored_hashed_password
        else:
            return False  # User not found

    # Verify the password
    if verifyPassword(username, password, conn):
        print("Password verification successful!")
    else:
        print("Password verification failed.")

    conn.close()  # Close the database connection when done

