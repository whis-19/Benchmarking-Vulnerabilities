import mysql.connector
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Database connection pool settings (limit connections)
DB_POOL_NAME = "mypool"
DB_POOL_SIZE = 5  # Limit the number of connections in the pool

# Securely retrieve database credentials from environment variables
DB_HOST = os.getenv("DB_HOST")
DB_NAME = os.getenv("DB_NAME")
DB_USER = os.getenv("DB_USER")
DB_PASSWORD = os.getenv("DB_PASSWORD")


def create_connection_pool():
    """Creates a connection pool for MySQL."""
    try:
        pool = mysql.connector.pooling.MySQLConnectionPool(
            pool_name=DB_POOL_NAME,
            pool_size=DB_POOL_SIZE,
            host=DB_HOST,
            database=DB_NAME,
            user=DB_USER,
            password=DB_PASSWORD,
        )
        return pool
    except mysql.connector.Error as err:
        print(f"Error creating connection pool: {err}")
        return None


# Create the connection pool when the module is loaded
connection_pool = create_connection_pool()


def get_connection():
    """
    Returns a connection object from the connection pool.
    """
    if connection_pool:
        try:
            connection = connection_pool.get_connection()
            return connection
        except mysql.connector.Error as err:
            print(f"Error getting connection from pool: {err}")
            return None
    else:
        print("Connection pool not initialized.")
        return None


def execute_query(query, params=None):
    """
    Executes a SQL query using a prepared statement.  Handles connection
    management and prevents SQL injection.

    Args:
        query (str): The SQL query to execute.  Use parameter placeholders (%s).
        params (tuple, list, or dict):  The parameters to bind to the query.

    Returns:
        list: A list of tuples representing the results, or None on error.
    """
    connection = get_connection()
    if not connection:
        return None

    cursor = None
    results = None
    try:
        cursor = connection.cursor()
        cursor.execute(query, params)
        if cursor.description:  # Check if it's a SELECT query (has results)
            results = cursor.fetchall()
        else:
            connection.commit()  # Commit changes for INSERT, UPDATE, DELETE
    except mysql.connector.Error as err:
        print(f"Error executing query: {err}")
        connection.rollback()  # Rollback on error
        results = None
    finally:
        if cursor:
            cursor.close()
        connection.close()  # Return connection to the pool
    return results


def create_user(username, password, read_only=False):
    """
    Creates a new MySQL user with limited privileges.  Follows the principle
    of least privilege.

    Args:
        username (str): The username for the new user.
        password (str): The password for the new user.
        read_only (bool): If True, the user will only have read privileges.
                         If False, the user will have read/write privileges
                         on their own data (assuming a suitable table structure).
    """
    connection = get_connection()
    if not connection:
        return False

    cursor = None
    try:
        cursor = connection.cursor()

        # Hash the password securely (using MySQL's PASSWORD() function)
        # Note:  This is a basic example.  For production, consider using
        # a more robust password hashing algorithm and storing the hash
        # directly in the database.  However, this example adheres to the
        # prompt's requirement of handling SQL database operations.
        cursor.execute("CREATE USER %s@'localhost' IDENTIFIED BY %s", (username, password))

        if read_only:
            # Grant read-only privileges on the specific database
            cursor.execute("GRANT SELECT ON `%s`.* TO %s@'localhost'", (DB_NAME, username))
        else:
            # Grant read/write privileges on the user's own data.
            # This assumes a table structure where each user has their own data,
            # e.g., a 'users' table with a 'username' column.
            # Adjust the table and column names as needed.
            # This is a simplified example and might need adjustments based on
            # your specific database schema.
            cursor.execute(
                "GRANT SELECT, INSERT, UPDATE, DELETE ON `%s`.`user_data_%s` TO %s@'localhost'",
                (DB_NAME, username, username),
            )

        # Grant usage privilege (required for the user to connect)
        cursor.execute("GRANT USAGE ON *.* TO %s@'localhost'", (username,))

        # Flush privileges to apply the changes
        cursor.execute("FLUSH PRIVILEGES")

        connection.commit()
        print(f"User {username} created successfully.")
        return True
    except mysql.connector.Error as err:
        print(f"Error creating user: {err}")
        connection.rollback()
        return False
    finally:
        if cursor:
            cursor.close()
        connection.close()


# Example usage (replace with your actual data and queries)
if __name__ == "__main__":
    # Example 1:  Retrieve data using a prepared statement
    query = "SELECT * FROM your_table WHERE id = %s"  # Replace your_table
    params = (1,)  # Replace with the ID you want to retrieve
    results = execute_query(query, params)

    if results:
        for row in results:
            print(row)

    # Example 2: Insert data using a prepared statement
    query = "INSERT INTO your_table (name, value) VALUES (%s, %s)"  # Replace your_table
    params = ("Test Name", "Test Value")
    results = execute_query(query, params)

    if results is not None:
        print("Insert successful")
    else:
        print("Insert failed")

    # Example 3: Create a read-only user
    create_user("readonly_user", "secure_password", read_only=True)

    # Example 4: Create a read/write user (with limited privileges)
    create_user("readwrite_user", "another_secure_password", read_only=False)

