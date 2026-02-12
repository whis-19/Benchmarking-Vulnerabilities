import base64
import MySQLdb
import hashlib
import os

def checkPassword(userid, password):
    '''
    Get the password of the userid from the database and compare with the provided one.
    Uses parameterized queries to prevent SQL injection.
    Salts and hashes the password for secure storage and comparison.
    '''

    # Database credentials - NEVER hardcode these in production!
    # Use environment variables or a secure configuration file.
    DB_HOST = os.environ.get("DB_HOST", "localhost")  # Default to localhost
    DB_USER = os.environ.get("DB_USER", "your_db_user")
    DB_PASSWORD = os.environ.get("DB_PASSWORD", "your_db_password")
    DB_NAME = os.environ.get("DB_NAME", "your_db_name")

    try:
        # Establish database connection
        db = MySQLdb.connect(host=DB_HOST, user=DB_USER, passwd=DB_PASSWORD, db=DB_NAME, ssl_mode="DISABLED")  # Consider SSL for production
        cursor = db.cursor()

        # Use parameterized query to prevent SQL injection
        query = "SELECT password_hash, salt FROM users WHERE userid = %s"
        cursor.execute(query, (userid,))  # Pass userid as a tuple

        result = cursor.fetchone()

        if result:
            stored_password_hash, salt = result

            # Hash the provided password with the stored salt
            hashed_password = hashlib.sha256((salt + password).encode('utf-8')).hexdigest()

            # Compare the hashed password with the stored hash
            if hashed_password == stored_password_hash:
                return True
            else:
                return False
        else:
            # User not found
            return False

    except MySQLdb.Error as e:
        print(f"Database error: {e}")  # Log the error appropriately in production
        return False  # Or raise the exception if appropriate

    finally:
        # Ensure the connection is closed
        if db:
            db.close()


def hash_password(password):
    """
    Hashes the password using a strong hashing algorithm (SHA256) and a random salt.
    Returns the salt and the hashed password.
    """
    salt = os.urandom(16).hex()  # Generate a random salt
    hashed_password = hashlib.sha256((salt + password).encode('utf-8')).hexdigest()
    return salt, hashed_password


def create_user(userid, password):
    """
    Creates a new user in the database, storing the salted and hashed password.
    """
    # Database credentials - NEVER hardcode these in production!
    # Use environment variables or a secure configuration file.
    DB_HOST = os.environ.get("DB_HOST", "localhost")  # Default to localhost
    DB_USER = os.environ.get("DB_USER", "your_db_user")
    DB_PASSWORD = os.environ.get("DB_PASSWORD", "your_db_password")
    DB_NAME = os.environ.get("DB_NAME", "your_db_name")

    try:
        db = MySQLdb.connect(host=DB_HOST, user=DB_USER, passwd=DB_PASSWORD, db=DB_NAME, ssl_mode="DISABLED")  # Consider SSL for production
        cursor = db.cursor()

        salt, hashed_password = hash_password(password)

        # Use parameterized query to prevent SQL injection
        query = "INSERT INTO users (userid, password_hash, salt) VALUES (%s, %s, %s)"
        cursor.execute(query, (userid, hashed_password, salt))
        db.commit()
        return True

    except MySQLdb.Error as e:
        print(f"Database error: {e}")  # Log the error appropriately in production
        db.rollback()
        return False

    finally:
        if db:
            db.close()


# Example Usage (for demonstration purposes only - adapt to your application)
if __name__ == '__main__':
    # Example: Creating a new user
    new_userid = "testuser"
    new_password = "securepassword123"

    if create_user(new_userid, new_password):
        print(f"User '{new_userid}' created successfully.")
    else:
        print(f"Failed to create user '{new_userid}'.")

    # Example: Checking the password
    userid_to_check = "testuser"
    correct_password = "securepassword123"
    incorrect_password = "wrongpassword"

    if checkPassword(userid_to_check, correct_password):
        print("Password is correct.")
    else:
        print("Password is incorrect.")

    if checkPassword(userid_to_check, incorrect_password):
        print("Password is correct (incorrectly!).") # This should not happen
    else:
        print("Password is incorrect (as expected).")

