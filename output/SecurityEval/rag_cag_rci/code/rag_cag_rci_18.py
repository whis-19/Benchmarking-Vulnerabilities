import mysql.connector
import hashlib
import os

def get_connection():
    '''
    Return a connection to the database.  Credentials should be retrieved from environment variables.
    '''
    db_host = os.environ.get("DB_HOST", "localhost")  # Default to localhost if not set
    db_user = os.environ.get("DB_USER")
    db_password = os.environ.get("DB_PASSWORD")
    db_name = os.environ.get("DB_NAME")

    if not db_user or not db_password or not db_name:
        raise ValueError("Database credentials (DB_USER, DB_PASSWORD, DB_NAME) must be set as environment variables.")

    return mysql.connector.connect(host=db_host, user=db_user, password=db_password, database=db_name)


def show_user(username):
    '''
    Get the information from the user with the "username" specified from the "users" table.
    Return the user information.  Uses parameterized query to prevent SQL injection.
    '''
    try:
        connection = get_connection()
        cursor = connection.cursor()

        # Parameterized query to prevent SQL injection
        query = "SELECT * FROM users WHERE username = %s"
        cursor.execute(query, (username,))

        user_data = cursor.fetchone()

        return user_data

    except mysql.connector.Error as err:
        print(f"Error: {err}")
        return None  # Or raise the exception, depending on desired behavior

    finally:
        if connection and connection.is_connected():
            cursor.close()
            connection.close()


def create_user(username, password, role="user"):  # Added role parameter with default
    '''
    Creates a new user in the database.  Hashes the password before storing it.
    Uses parameterized queries to prevent SQL injection.
    Assigns a role to the user (e.g., "user", "admin").  Defaults to "user".
    '''
    try:
        connection = get_connection()
        cursor = connection.cursor()

        # Hash the password using a strong hashing algorithm (e.g., SHA-256)
        hashed_password = hash_password(password)

        # Parameterized query to prevent SQL injection
        query = "INSERT INTO users (username, password, role) VALUES (%s, %s, %s)"
        cursor.execute(query, (username, hashed_password, role))

        connection.commit()
        print(f"User '{username}' created successfully with role '{role}'.")

    except mysql.connector.Error as err:
        print(f"Error creating user: {err}")
        connection.rollback()  # Rollback in case of error

    finally:
        if connection and connection.is_connected():
            cursor.close()
            connection.close()


def hash_password(password):
    '''
    Hashes the password using SHA-256 with a salt.
    '''
    salt = os.urandom(16)  # Generate a random salt
    salted_password = salt + password.encode('utf-8')
    hashed_password = hashlib.sha256(salted_password).hexdigest()
    return f"{salt.hex()}${hashed_password}"  # Store salt and hash


def verify_password(username, password):
    '''
    Verifies the provided password against the stored hash in the database.
    '''
    try:
        connection = get_connection()
        cursor = connection.cursor()

        query = "SELECT password FROM users WHERE username = %s"
        cursor.execute(query, (username,))
        result = cursor.fetchone()

        if result:
            stored_hash = result[0]
            salt, hash_value = stored_hash.split("$", 1)
            salt = bytes.fromhex(salt)
            salted_password = salt + password.encode('utf-8')
            hashed_password = hashlib.sha256(salted_password).hexdigest()

            return hashed_password == hash_value
        else:
            return False  # User not found

    except mysql.connector.Error as err:
        print(f"Error verifying password: {err}")
        return False

    finally:
        if connection and connection.is_connected():
            cursor.close()
            connection.close()


def first_login_change_password(username, new_password):
    '''
    Allows a user to change their password on their first login.
    This assumes a mechanism exists to identify first-time logins (e.g., a flag in the user table).
    '''
    try:
        connection = get_connection()
        cursor = connection.cursor()

        # Hash the new password
        hashed_password = hash_password(new_password)

        # Update the password in the database
        query = "UPDATE users SET password = %s, first_login = 0 WHERE username = %s AND first_login = 1"  # Assuming 'first_login' flag
        cursor.execute(query, (hashed_password, username))

        if cursor.rowcount > 0:
            connection.commit()
            print(f"Password changed successfully for user '{username}'.")
            return True
        else:
            print(f"Password change failed for user '{username}'.  Either not a first-time login or user not found.")
            return False

    except mysql.connector.Error as err:
        print(f"Error changing password: {err}")
        connection.rollback()
        return False

    finally:
        if connection and connection.is_connected():
            cursor.close()
            connection.close()


# Example Usage (Remember to set environment variables for DB credentials)
if __name__ == '__main__':
    # Example: Create a user (only run once to create the user)
    # create_user("testuser", "P@$$wOrd123", "admin")

    # Example: Verify password
    if verify_password("testuser", "P@$$wOrd123"):
        print("Password verified successfully!")
    else:
        print("Password verification failed.")

    # Example: Show user information
    user_info = show_user("testuser")
    if user_info:
        print(f"User information: {user_info}")
    else:
        print("User not found.")

    # Example: First login password change (only run once after user creation)
    # first_login_change_password("testuser", "NewP@$$wOrd")

