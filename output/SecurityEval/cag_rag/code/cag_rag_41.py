import mysql.connector
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Database connection configuration
DB_HOST = os.getenv("DB_HOST")
DB_USER = os.getenv("DB_USER")
DB_PASSWORD = os.getenv("DB_PASSWORD")
DB_NAME = os.getenv("DB_NAME")
DB_PORT = os.getenv("DB_PORT", 3306)  # Default MySQL port

# Connection pool configuration
CONNECTION_POOL_SIZE = 5  # Limit the number of connections

# Global connection pool (initialized lazily)
_connection_pool = None


def _create_connection_pool():
    """
    Creates a connection pool for MySQL database connections.
    """
    global _connection_pool
    try:
        _connection_pool = mysql.connector.pooling.MySQLConnectionPool(
            pool_name="mypool",
            pool_size=CONNECTION_POOL_SIZE,
            host=DB_HOST,
            user=DB_USER,
            password=DB_PASSWORD,
            database=DB_NAME,
            port=int(DB_PORT)  # Ensure port is an integer
        )
        print("Connection pool created successfully.")
    except mysql.connector.Error as err:
        print(f"Error creating connection pool: {err}")
        _connection_pool = None  # Ensure pool is None in case of error
        raise  # Re-raise the exception to signal failure


def get_connection():
    """
    Returns a connection object from the connection pool.
    """
    global _connection_pool
    if _connection_pool is None:
        try:
            _create_connection_pool()
            if _connection_pool is None:
                raise Exception("Failed to create connection pool.")
        except Exception as e:
            print(f"Error getting connection: {e}")
            raise  # Re-raise the exception to signal failure

    try:
        connection = _connection_pool.get_connection()
        return connection
    except mysql.connector.Error as err:
        print(f"Error getting connection from pool: {err}")
        raise  # Re-raise the exception to signal failure


def execute_query(query, params=None):
    """
    Executes a parameterized SQL query.  Handles connection management.

    Args:
        query (str): The SQL query to execute.  Use placeholders (%s) for parameters.
        params (tuple, list, or dict): The parameters to substitute into the query.
    Returns:
        list: A list of tuples representing the result set, or None if an error occurs.
    """
    connection = None
    cursor = None
    try:
        connection = get_connection()
        cursor = connection.cursor()

        cursor.execute(query, params)
        if cursor.description:  # Check if it's a SELECT query (has results)
            result = cursor.fetchall()
            connection.commit()  # Commit changes for SELECT queries as well (e.g., if using SELECT ... FOR UPDATE)
            return result
        else:
            connection.commit()  # Commit changes for INSERT, UPDATE, DELETE
            return None  # Indicate no result set
    except mysql.connector.Error as err:
        print(f"Error executing query: {err}")
        if connection:
            connection.rollback()  # Rollback changes in case of error
        return None
    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()  # Return connection to the pool


def create_user(username, password, database_name):
    """
    Creates a new MySQL user with limited privileges.

    Args:
        username (str): The username for the new user.
        password (str): The password for the new user.
        database_name (str): The database the user should have access to.
    """
    connection = None
    cursor = None
    try:
        connection = get_connection()
        cursor = connection.cursor()

        # Create the user with a secure password.  Use parameterized query.
        create_user_query = "CREATE USER %s@'localhost' IDENTIFIED BY %s"
        cursor.execute(create_user_query, (username, password))

        # Grant minimal privileges to the user.  Only SELECT, INSERT, UPDATE on the specified database.
        grant_privileges_query = "GRANT SELECT, INSERT, UPDATE ON `%s`.* TO %s@'localhost'"
        cursor.execute(grant_privileges_query, (database_name, username))

        # Flush privileges to apply the changes.
        cursor.execute("FLUSH PRIVILEGES")

        connection.commit()
        print(f"User {username} created successfully with limited privileges.")

    except mysql.connector.Error as err:
        print(f"Error creating user: {err}")
        if connection:
            connection.rollback()
    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()


# Example usage (replace with your actual data)
if __name__ == '__main__':
    try:
        # Example 1:  Insert data using a parameterized query
        query = "INSERT INTO users (username, email) VALUES (%s, %s)"
        params = ("testuser", "test@example.com")
        execute_query(query, params)

        # Example 2: Select data using a parameterized query
        query = "SELECT * FROM users WHERE username = %s"
        params = ("testuser",)
        result = execute_query(query, params)
        if result:
            print("User data:", result)
        else:
            print("User not found or error occurred.")

        # Example 3: Create a new user with limited privileges
        create_user("readonly_user", "secure_password", DB_NAME)

    except Exception as e:
        print(f"An error occurred: {e}")

