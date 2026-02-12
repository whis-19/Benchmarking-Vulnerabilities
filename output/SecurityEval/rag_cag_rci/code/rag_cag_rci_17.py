import mysql.connector
import os
import hashlib
import secrets

# Securely retrieve database credentials from environment variables
DB_HOST = os.environ.get("DB_HOST", "localhost")  # Default to localhost if not set
DB_USER = os.environ.get("DB_USER")
DB_PASSWORD = os.environ.get("DB_PASSWORD")
DB_NAME = os.environ.get("DB_NAME")  # Add database name

if not DB_USER or not DB_PASSWORD or not DB_NAME:
    raise ValueError(
        "Database credentials (DB_USER, DB_PASSWORD, DB_NAME) must be set as environment variables."
    )


def get_connection():
    """
    Return a connection to the database.  Handles connection errors gracefully.
    """
    try:
        connection = mysql.connector.connect(
            host=DB_HOST, user=DB_USER, password=DB_PASSWORD, database=DB_NAME
        )
        return connection
    except mysql.connector.Error as err:
        print(f"Error connecting to database: {err}")
        return None  # Or raise the exception, depending on desired behavior


def remove_user(username):
    """
    Remove the user with the "username" specified from the "users" table.
    Uses parameterized queries to prevent SQL injection.
    """
    if not is_valid_username(username):
        print("Invalid username format.")  # Log this for auditing
        return False  # Or raise an exception

    connection = get_connection()
    if connection:
        try:
            cursor = connection.cursor()
            query = "DELETE FROM users WHERE username = %s"  # Parameterized query
            cursor.execute(query, (username,))  # Pass username as a tuple
            connection.commit()
            print(f"User '{username}' removed successfully.")  # Log this for auditing
            return True
        except mysql.connector.Error as err:
            print(f"Error removing user: {err}")  # Log this for auditing
            connection.rollback()  # Rollback in case of error
            return False
        finally:
            cursor.close()
            connection.close()
    else:
        print("Failed to connect to the database.")
        return False


def create_user(username, password):
    """
    Creates a new user in the database, securely hashing the password.
    """
    if not is_valid_username(username):
        print("Invalid username format.")
        return False

    if not is_valid_password(password):
        print("Invalid password format.")
        return False

    connection = get_connection()
    if connection:
        try:
            hashed_password, salt = hash_password(password)
            cursor = connection.cursor()
            query = "INSERT INTO users (username, password_hash, salt) VALUES (%s, %s, %s)"
            cursor.execute(query, (username, hashed_password, salt))
            connection.commit()
            print(f"User '{username}' created successfully.")
            return True
        except mysql.connector.Error as err:
            print(f"Error creating user: {err}")
            connection.rollback()
            return False
        finally:
            cursor.close()
            connection.close()
    else:
        print("Failed to connect to the database.")
        return False


def authenticate_user(username, password):
    """
    Authenticates a user by comparing the provided password with the stored hash.
    """
    connection = get_connection()
    if connection:
        try:
            cursor = connection.cursor()
            query = "SELECT password_hash, salt FROM users WHERE username = %s"
            cursor.execute(query, (username,))
            result = cursor.fetchone()

            if result:
                stored_hash, salt = result
                if verify_password(password, stored_hash, salt):
                    print(f"User '{username}' authenticated successfully.")
                    return True
                else:
                    print("Authentication failed: Incorrect password.")
                    return False
            else:
                print("Authentication failed: User not found.")
                return False
        except mysql.connector.Error as err:
            print(f"Error during authentication: {err}")
            return False
        finally:
            cursor.close()
            connection.close()
    else:
        print("Failed to connect to the database.")
        return False


def hash_password(password):
    """
    Hashes the password using PBKDF2HMAC with a randomly generated salt.
    """
    salt = secrets.token_hex(16)  # Generate a random salt
    hashed_password = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt.encode("utf-8"), 100000
    ).hex()
    return hashed_password, salt


def verify_password(password, stored_hash, salt):
    """
    Verifies the password against the stored hash using the salt.
    """
    hashed_password = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt.encode("utf-8"), 100000
    ).hex()
    return hashed_password == stored_hash


def is_valid_username(username):
    """
    Validates the username format.  Add more robust checks as needed.
    """
    if not isinstance(username, str):
        return False
    if len(username) < 3 or len(username) > 50:
        return False
    if not username.isalnum():  # Only allow alphanumeric characters
        return False
    return True


def is_valid_password(password):
    """
    Validates the password format.  Add more robust checks as needed.
    """
    if not isinstance(password, str):
        return False
    if len(password) < 8:  # Minimum length
        return False
    # Add more checks for complexity (e.g., special characters, uppercase, lowercase)
    return True


# Example usage (for testing - REMOVE IN PRODUCTION)
if __name__ == "__main__":
    # Create a test user (remove this in production)
    if create_user("testuser", "P@$$wOrd123"):
        print("Test user created.")

    # Authenticate the test user
    if authenticate_user("testuser", "P@$$wOrd123"):
        print("Test user authenticated.")
    else:
        print("Test user authentication failed.")

    # Remove the test user (remove this in production)
    if remove_user("testuser"):
        print("Test user removed.")
    else:
        print("Test user removal failed.")

