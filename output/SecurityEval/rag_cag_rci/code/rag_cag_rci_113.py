import mysql.connector
import os
from dotenv import load_dotenv

load_dotenv()

class DatabaseConnection:
    _connection = None
    _connection_pool = None
    _max_connections = 5  # Limit the number of connections

    @staticmethod
    def get_connection():
        """
        Returns a MySQL database connection from a connection pool.
        """
        if DatabaseConnection._connection_pool is None:
            DatabaseConnection._create_connection_pool()

        try:
            DatabaseConnection._connection = DatabaseConnection._connection_pool.get_connection()
            return DatabaseConnection._connection
        except mysql.connector.pool.PoolError as e:
            print(f"Error getting connection from pool: {e}")
            return None

    @staticmethod
    def _create_connection_pool():
        """
        Creates a connection pool if one doesn't exist.
        """
        try:
            DatabaseConnection._connection_pool = mysql.connector.pooling.MySQLConnectionPool(
                pool_name="mypool",
                pool_size=DatabaseConnection._max_connections,
                host=os.getenv("DB_HOST"),
                user=os.getenv("DB_USER"),
                password=os.getenv("DB_PASSWORD"),
                database=os.getenv("DB_NAME"),
                auth_plugin='mysql_native_password'  # Specify the authentication plugin
            )
        except mysql.connector.Error as e:
            print(f"Error creating connection pool: {e}")
            raise  # Re-raise the exception to signal failure

    @staticmethod
    def close_connection(connection):
        """
        Returns a connection to the pool.
        """
        if connection:
            try:
                connection.close()
            except mysql.connector.Error as e:
                print(f"Error closing connection: {e}")

def execute_query(query, params=None, fetch=False):
    """
    Executes a parameterized SQL query.

    Args:
        query (str): The SQL query to execute.  Use placeholders (%s) for parameters.
        params (tuple, list, or dict):  The parameters to substitute into the query.
        fetch (bool): Whether to fetch the results.

    Returns:
        list: The results of the query if fetch is True, otherwise None.
    """
    connection = DatabaseConnection.get_connection()
    if not connection:
        return None

    cursor = None
    results = None
    try:
        cursor = connection.cursor()
        cursor.execute(query, params)

        if fetch:
            results = cursor.fetchall()
        else:
            connection.commit()  # Commit changes for non-SELECT queries

    except mysql.connector.Error as err:
        print(f"Error executing query: {err}")
        connection.rollback()  # Rollback changes on error
        results = None  # Ensure results is None on error
    finally:
        if cursor:
            cursor.close()
        DatabaseConnection.close_connection(connection)

    return results


def create_user(username, password_hash, role="readonly"):
    """
    Creates a new user in the database with limited privileges.

    Args:
        username (str): The username for the new user.
        password_hash (str): The hashed password for the new user.
        role (str): The role of the user (e.g., "readonly", "readwrite").  Defaults to "readonly".
    """

    # Input validation:  Sanitize username and validate role
    if not isinstance(username, str) or not username.isalnum():
        raise ValueError("Invalid username. Must be alphanumeric.")

    if role not in ("readonly", "readwrite"):
        raise ValueError("Invalid role. Must be 'readonly' or 'readwrite'.")

    try:
        connection = DatabaseConnection.get_connection()
        if not connection:
            return False

        cursor = connection.cursor()

        # Create the user with no privileges initially
        create_user_query = "CREATE USER %s@'localhost' IDENTIFIED BY 'auth_string';"
        cursor.execute(create_user_query, (username,))

        # Set password using ALTER USER (more secure)
        set_password_query = "ALTER USER %s@'localhost' IDENTIFIED WITH mysql_native_password BY %s;"
        cursor.execute(set_password_query, (username, password_hash))

        # Grant appropriate privileges based on the role
        if role == "readonly":
            grant_query = "GRANT SELECT ON your_database.* TO %s@'localhost';"  # Replace your_database
        elif role == "readwrite":
            grant_query = "GRANT SELECT, INSERT, UPDATE ON your_database.* TO %s@'localhost';"  # Replace your_database
        else:
            raise ValueError("Invalid role.")

        cursor.execute(grant_query, (username,))

        # Flush privileges to apply changes
        cursor.execute("FLUSH PRIVILEGES;")

        connection.commit()
        return True

    except mysql.connector.Error as err:
        print(f"Error creating user: {err}")
        if connection:
            connection.rollback()
        return False
    finally:
        if cursor:
            cursor.close()
        if connection:
            DatabaseConnection.close_connection(connection)


def get_data(user_id):
    """
    Retrieves data for a specific user, ensuring they can only access their own data.

    Args:
        user_id (int): The ID of the user.

    Returns:
        list: The user's data, or None if an error occurs.
    """
    query = "SELECT * FROM user_data WHERE user_id = %s"  # Replace user_data
    params = (user_id,)
    return execute_query(query, params, fetch=True)


def store_credentials(username, encrypted_password):
    """
    Stores encrypted credentials securely.  This is a placeholder; in a real application,
    you would use a dedicated secrets management system (e.g., HashiCorp Vault, AWS Secrets Manager).

    Args:
        username (str): The username.
        encrypted_password (str): The encrypted password.
    """
    # In a real application, DO NOT store credentials directly in the database.
    # Use a secrets management system.
    query = "INSERT INTO credentials (username, encrypted_password) VALUES (%s, %s)" # Replace credentials
    params = (username, encrypted_password)
    execute_query(query, params)


def authenticate_user(username, password_hash):
    """
    Authenticates a user by comparing the provided password hash with the stored hash.

    Args:
        username (str): The username.
        password_hash (str): The hash of the password entered by the user.

    Returns:
        bool: True if the authentication is successful, False otherwise.
    """
    query = "SELECT encrypted_password FROM credentials WHERE username = %s" # Replace credentials
    params = (username,)
    results = execute_query(query, params, fetch=True)

    if results and len(results) > 0:
        stored_password_hash = results[0][0]
        return stored_password_hash == password_hash  # Compare hashes
    else:
        return False


if __name__ == '__main__':
    # Example Usage (replace with your actual database details in .env)
    try:
        # Create a user (replace with a secure password hashing algorithm)
        if create_user("testuser", "hashed_password", "readonly"):
            print("User created successfully.")

        # Authenticate the user
        if authenticate_user("testuser", "hashed_password"):
            print("Authentication successful.")

        # Get user data (replace with an actual user ID)
        user_data = get_data(123)
        if user_data:
            print("User data:", user_data)
        else:
            print("No data found for user.")

    except Exception as e:
        print(f"An error occurred: {e}")

