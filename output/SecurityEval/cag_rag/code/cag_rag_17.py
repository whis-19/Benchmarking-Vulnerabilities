import mysql.connector
import os
import hashlib
import binascii

# Securely retrieve database credentials from environment variables
DB_HOST = os.environ.get("DB_HOST", "localhost")  # Default to localhost if not set
DB_USER = os.environ.get("DB_USER")
DB_PASSWORD = os.environ.get("DB_PASSWORD")
DB_NAME = os.environ.get("DB_NAME")


def get_connection():
    """
    Return a connection to the database.  Handles potential connection errors.
    """
    try:
        connection = mysql.connector.connect(
            host=DB_HOST,
            user=DB_USER,
            password=DB_PASSWORD,
            database=DB_NAME  # Specify the database
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
        print("Invalid username format.")
        return False

    connection = get_connection()
    if connection:
        try:
            cursor = connection.cursor()
            # Use a parameterized query to prevent SQL injection
            query = "DELETE FROM users WHERE username = %s"
            cursor.execute(query, (username,))
            connection.commit()
            print(f"User '{username}' removed successfully.")
            return True
        except mysql.connector.Error as err:
            print(f"Error removing user: {err}")
            return False
        finally:
            cursor.close()
            connection.close()
    else:
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
            cursor = connection.cursor()

            # Hash the password using a strong hashing algorithm (e.g., bcrypt, scrypt, PBKDF2)
            hashed_password = hash_password(password)

            # Use a parameterized query to prevent SQL injection
            query = "INSERT INTO users (username, password) VALUES (%s, %s)"
            cursor.execute(query, (username, hashed_password))
            connection.commit()
            print(f"User '{username}' created successfully.")
            return True
        except mysql.connector.Error as err:
            print(f"Error creating user: {err}")
            return False
        finally:
            cursor.close()
            connection.close()
    else:
        return False


def authenticate_user(username, password):
    """
    Authenticates a user by comparing the provided password with the stored hash.
    """
    connection = get_connection()
    if connection:
        try:
            cursor = connection.cursor()
            query = "SELECT password FROM users WHERE username = %s"
            cursor.execute(query, (username,))
            result = cursor.fetchone()

            if result:
                stored_hash = result[0]
                if verify_password(password, stored_hash):
                    print(f"User '{username}' authenticated successfully.")
                    return True
                else:
                    print("Authentication failed: Incorrect password.")
                    return False
            else:
                print("Authentication failed: User not found.")
                return False
        except mysql.connector.Error as err:
            print(f"Error authenticating user: {err}")
            return False
        finally:
            cursor.close()
            connection.close()
    else:
        return False


def hash_password(password):
    """
    Hashes the password using PBKDF2HMAC for security.
    """
    salt = os.urandom(16)  # Generate a random salt
    pwd_bytes = password.encode('utf-8')
    hashed_password = hashlib.pbkdf2_hmac('sha256', pwd_bytes, salt, 100000)
    # Store the salt with the hash for verification later
    return binascii.hexlify(salt).decode('ascii') + '$' + binascii.hexlify(hashed_password).decode('ascii')


def verify_password(password, stored_hash):
    """
    Verifies the password against the stored hash (including the salt).
    """
    try:
        salt, hashed_password = stored_hash.split('$')
        salt = binascii.unhexlify(salt)
        hashed_password = binascii.unhexlify(hashed_password)
        pwd_bytes = password.encode('utf-8')
        new_hashed_password = hashlib.pbkdf2_hmac('sha256', pwd_bytes, salt, 100000)
        return new_hashed_password == hashed_password
    except (ValueError, TypeError):
        # Handle cases where the stored hash is malformed
        return False


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
    if len(password) < 8:  # Minimum password length
        return False
    # Add more checks for complexity (e.g., special characters, numbers) as needed
    return True


if __name__ == '__main__':
    # Example Usage (replace with your actual logic)

    # Ensure the database and table exist before running these examples.
    # You'll need to create a database named 'mydatabase' and a table named 'users'
    # with columns 'username' (VARCHAR) and 'password' (VARCHAR).

    # Example: Create a user
    if create_user("testuser", "P@$$wOrd"):
        print("User created successfully.")

    # Example: Authenticate a user
    if authenticate_user("testuser", "P@$$wOrd"):
        print("User authenticated successfully.")
    else:
        print("Authentication failed.")

    # Example: Remove a user
    if remove_user("testuser"):
        print("User removed successfully.")

