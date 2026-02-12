import mysql.connector
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Database connection pool settings
DB_POOL_NAME = "mypool"
DB_POOL_SIZE = 5  # Limit the number of connections in the pool

# Securely retrieve database credentials from environment variables
DB_HOST = os.getenv("DB_HOST")
DB_USER = os.getenv("DB_USER")
DB_PASSWORD = os.getenv("DB_PASSWORD")
DB_NAME = os.getenv("DB_NAME")

# Check if environment variables are set
if not all([DB_HOST, DB_USER, DB_PASSWORD, DB_NAME]):
    raise ValueError("Database credentials not found in environment variables.")


def get_db_connection():
    """
    Returns a MySQL database connection from a connection pool.
    Handles connection limits and secure credential retrieval.
    """
    try:
        # Check if the connection pool exists, create if it doesn't
        if DB_POOL_NAME not in mysql.connector.connection_pools:
            db_config = {
                "host": DB_HOST,
                "user": DB_USER,
                "password": DB_PASSWORD,
                "database": DB_NAME,
                "auth_plugin": 'mysql_native_password'  # Specify authentication plugin
            }
            mysql.connector.pooling.MySQLConnectionPool(
                pool_name=DB_POOL_NAME,
                pool_size=DB_POOL_SIZE,
                **db_config
            )

        # Get a connection from the pool
        connection = mysql.connector.connection_pools.get_connection(pool_name=DB_POOL_NAME)
        return connection

    except mysql.connector.Error as err:
        print(f"Error connecting to the database: {err}")
        return None


def execute_query(query, params=None):
    """
    Executes a SQL query using parameterized queries for security.
    Handles connection management and error handling.
    """
    connection = get_db_connection()
    if connection:
        cursor = connection.cursor()
        try:
            cursor.execute(query, params)
            connection.commit()  # Commit changes for INSERT, UPDATE, DELETE
            return cursor
        except mysql.connector.Error as err:
            print(f"Error executing query: {err}")
            connection.rollback()  # Rollback on error
            return None
        finally:
            cursor.close()
            connection.close()  # Return connection to the pool
    else:
        return None


def fetch_data(query, params=None, cache=True):
    """
    Fetches data from the database using parameterized queries and caching.
    """
    connection = get_db_connection()
    if connection:
        cursor = connection.cursor()
        try:
            cursor.execute(query, params)
            results = cursor.fetchall()

            # In a real application, implement a proper caching mechanism
            # (e.g., using Redis, Memcached, or a simple in-memory cache with TTL)
            if cache:
                # This is a placeholder for caching.  Do NOT store sensitive data in a simple in-memory cache in production.
                # Example:  cache[query + str(params)] = results
                pass  # Replace with actual caching logic

            return results
        except mysql.connector.Error as err:
            print(f"Error fetching data: {err}")
            return None
        finally:
            cursor.close()
            connection.close()
    else:
        return None


def create_user(username, password, read_only=True):
    """
    Creates a new MySQL user with limited privileges (read-only by default).
    Uses parameterized queries to prevent SQL injection.
    """
    connection = get_db_connection()
    if connection:
        cursor = connection.cursor()
        try:
            # Hash the password securely (using bcrypt, scrypt, or Argon2)
            # For demonstration purposes, we'll use a simple hash (NOT RECOMMENDED FOR PRODUCTION)
            hashed_password = password  # Replace with a proper hashing algorithm

            # Create the user with minimal privileges
            create_user_query = "CREATE USER %s@'localhost' IDENTIFIED BY %s"
            cursor.execute(create_user_query, (username, hashed_password))

            # Grant read-only privileges (or read/write if read_only is False)
            if read_only:
                grant_query = f"GRANT SELECT ON `{DB_NAME}`.* TO %s@'localhost'"
            else:
                grant_query = f"GRANT SELECT, INSERT, UPDATE, DELETE ON `{DB_NAME}`.* TO %s@'localhost'"

            cursor.execute(grant_query, (username,))

            connection.commit()
            print(f"User {username} created successfully with {'read-only' if read_only else 'read/write'} privileges.")
        except mysql.connector.Error as err:
            print(f"Error creating user: {err}")
            connection.rollback()
        finally:
            cursor.close()
            connection.close()
    else:
        print("Failed to connect to the database.")


# Example Usage (replace with your actual logic)
if __name__ == "__main__":
    # Example 1: Fetch data securely
    query = "SELECT * FROM users WHERE username = %s"
    params = ("testuser",)
    results = fetch_data(query, params)
    if results:
        print("Fetched data:", results)

    # Example 2: Insert data securely
    insert_query = "INSERT INTO users (username, email) VALUES (%s, %s)"
    insert_params = ("newuser", "newuser@example.com")
    cursor = execute_query(insert_query, insert_params)
    if cursor:
        print("Data inserted successfully.")

    # Example 3: Create a new user with read-only privileges
    create_user("readonlyuser", "securepassword", read_only=True)

    # Example 4: Create a new user with read/write privileges (use with caution!)
    # create_user("readwriteuser", "anothersecurepassword", read_only=False)

