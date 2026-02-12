import mysql.connector
import mysql.connector.pooling
import os
from dotenv import load_dotenv

load_dotenv()

# Database configuration loaded from environment variables
DB_HOST = os.getenv("DB_HOST", "localhost")
DB_USER = os.getenv("DB_USER")
DB_PASSWORD = os.getenv("DB_PASSWORD")
DB_NAME = os.getenv("DB_NAME")
CONNECTION_POOL_SIZE = int(os.getenv("CONNECTION_POOL_SIZE", "5"))  # Default to 5 if not set

# Connection pooling setup
db_config = {
    "host": DB_HOST,
    "user": DB_USER,
    "password": DB_PASSWORD,
    "database": DB_NAME,
}

connection_pool = mysql.connector.pooling.MySQLConnectionPool(
    pool_name="mypool", pool_size=CONNECTION_POOL_SIZE, **db_config
)


def get_connection():
    """
    Return a connection from the connection pool.
    Handles connection limits.
    """
    try:
        connection = connection_pool.get_connection()
        return connection
    except mysql.connector.Error as e:
        print(f"Error getting connection from pool: {e}")
        return None


def remove_user(username):
    """
    Remove the user with the "username" specified from the "users" table.
    Uses parameterized queries to prevent SQL injection.
    """
    connection = get_connection()
    if connection:
        try:
            cursor = connection.cursor()
            # Use parameterized query to prevent SQL injection
            query = "DELETE FROM users WHERE username = %s"
            cursor.execute(query, (username,))  # username is passed as a tuple

            connection.commit()
            print(f"User '{username}' removed successfully.")

        except mysql.connector.Error as err:
            print(f"Error removing user: {err}")
            connection.rollback()  # Rollback in case of error

        finally:
            cursor.close()
            connection.close()  # Return connection to the pool
    else:
        print("Failed to obtain a database connection.")


def create_user(username, password, role="readonly"):
    """
    Creates a new user in the database with limited privileges.
    Hashes the password before storing it.
    Uses parameterized queries to prevent SQL injection.
    """
    import bcrypt

    connection = get_connection()
    if connection:
        try:
            cursor = connection.cursor()

            # Hash the password
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

            # Insert user data (username, hashed password)
            insert_query = "INSERT INTO users (username, password) VALUES (%s, %s)"
            cursor.execute(insert_query, (username, hashed_password.decode('utf-8')))
            connection.commit()

            # Grant limited privileges based on the role
            if role == "readonly":
                grant_query = f"GRANT SELECT ON `{DB_NAME}`.* TO '{username}'@'localhost'"
            elif role == "readwrite":
                grant_query = f"GRANT SELECT, INSERT, UPDATE, DELETE ON `{DB_NAME}`.* TO '{username}'@'localhost'"
            else:
                print("Invalid role specified.  No privileges granted.")
                grant_query = None

            if grant_query:
                cursor.execute(grant_query)
                connection.commit()
                print(f"User '{username}' created with '{role}' privileges.")
            else:
                print(f"User '{username}' created, but no privileges granted due to invalid role.")

        except mysql.connector.Error as err:
            print(f"Error creating user: {err}")
            connection.rollback()

        finally:
            cursor.close()
            connection.close()
    else:
        print("Failed to obtain a database connection.")


def verify_password(username, password):
    """
    Verifies the provided password against the stored hash.
    """
    import bcrypt

    connection = get_connection()
    if connection:
        try:
            cursor = connection.cursor()
            query = "SELECT password FROM users WHERE username = %s"
            cursor.execute(query, (username,))
            result = cursor.fetchone()

            if result:
                hashed_password = result[0]
                if bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8')):
                    return True
                else:
                    return False
            else:
                return False  # User not found

        except mysql.connector.Error as err:
            print(f"Error verifying password: {err}")
            return False

        finally:
            cursor.close()
            connection.close()
    else:
        print("Failed to obtain a database connection.")
        return False


# Example Usage (Remember to set environment variables)
if __name__ == '__main__':
    # Example: Create a user (only run once to set up the initial admin)
    # create_user("admin", "P@$$wOrd", "readwrite") # NEVER hardcode passwords.  Use environment variables or secrets.

    # Example: Verify a password
    if verify_password("admin", os.getenv("ADMIN_PASSWORD")):  # Use environment variable for password
        print("Admin password verified.")
    else:
        print("Admin password verification failed.")

    # Example: Remove a user
    # remove_user("testuser")

