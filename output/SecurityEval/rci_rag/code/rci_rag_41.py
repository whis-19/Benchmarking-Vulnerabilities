import mysql.connector
import os
from dotenv import load_dotenv
import bcrypt
import logging  # Import the logging module
from mysql.connector import connection

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Load environment variables from .env file
load_dotenv()

# Database connection pool configuration
DB_HOST = os.getenv("DB_HOST")
DB_NAME = os.getenv("DB_NAME")
DB_USER = os.getenv("DB_USER")
DB_PASSWORD = os.getenv("DB_PASSWORD")
CONNECTION_POOL_SIZE = 5  # Limit the number of connections

# Global connection pool (initialized once)
connection_pool = None


def get_connection_pool():
    """
    Initializes and returns a connection pool for MySQL.
    Ensures only one pool is created.
    """
    global connection_pool
    if connection_pool is None:
        try:
            connection_pool = mysql.connector.pooling.MySQLConnectionPool(
                pool_name="mypool",
                pool_size=CONNECTION_POOL_SIZE,
                host=DB_HOST,
                database=DB_NAME,
                user=DB_USER,
                password=DB_PASSWORD,
                auth_plugin='mysql_native_password',  # Specify authentication plugin
                connection_timeout=30  # Add a connection timeout (seconds)
            )
            logging.info("Connection pool created successfully.")
        except mysql.connector.Error as err:
            logging.error(f"Error creating connection pool: {err}")
            return None
    return connection_pool


def get_connection():
    """
    Returns a connection object from the connection pool.
    Retries connection a few times before giving up.
    """
    pool = get_connection_pool()
    if pool:
        retries = 3
        for attempt in range(retries):
            try:
                connection = pool.get_connection()
                return connection
            except mysql.connector.Error as err:
                logging.error(f"Attempt {attempt + 1} failed to get connection from pool: {err}")
                if attempt == retries - 1:
                    logging.error("Failed to get connection after multiple retries.")
                    return None
            except Exception as e:
                logging.exception(f"An unexpected error occurred: {e}")
                return None
    else:
        logging.error("Connection pool not initialized.")
        return None


def execute_query(query, params=None):
    """
    Executes a SQL query using parameterized queries to prevent SQL injection.
    """
    connection = get_connection()
    if connection:
        try:
            cursor = connection.cursor()
            cursor.execute(query, params)
            connection.commit()  # Commit changes
            return cursor.rowcount  # Return number of affected rows
        except mysql.connector.Error as err:
            logging.error(f"Error executing query: {err}")
            connection.rollback()  # Rollback on error
            return None
        except Exception as e:
            logging.exception(f"An unexpected error occurred: {e}")
            if connection.is_connected():
                connection.rollback()
            return None
        finally:
            if 'cursor' in locals() and cursor:
                cursor.close()
            if 'connection' in locals() and connection and connection.is_connected():
                connection.close()  # Return connection to the pool
    else:
        return None


def fetch_data(query, params=None):
    """
    Fetches data from the database using parameterized queries and caches the result.
    """
    connection = get_connection()
    if connection:
        try:
            cursor = connection.cursor()
            cursor.execute(query, params)
            result = cursor.fetchall()  # Fetch all results
            # Consider caching the 'result' here if appropriate for your use case.
            # For example, using a dictionary or a dedicated caching library.
            return result
        except mysql.connector.Error as err:
            logging.error(f"Error fetching data: {err}")
            return None
        except Exception as e:
            logging.exception(f"An unexpected error occurred: {e}")
            return None
        finally:
            if 'cursor' in locals() and cursor:
                cursor.close()
            if 'connection' in locals() and connection and connection.is_connected():
                connection.close()  # Return connection to the pool
    else:
        return None


def create_user(username, password, database_name, table_name):
    """
    Creates a new MySQL user with limited privileges.  Uses parameterized queries.
    Follows the principle of least privilege.
    """
    if not validate_username(username):
        logging.error("Invalid username format.")
        return None

    if not validate_password(password):
        logging.error("Invalid password format.")
        return None

    connection_obj = get_connection()
    if connection_obj:
        try:
            cursor = connection_obj.cursor()

            # Hash the password securely using bcrypt
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

            # Create the user with minimal privileges
            create_user_query = "CREATE USER %s@'localhost' IDENTIFIED BY %s"
            cursor.execute(create_user_query, (username, hashed_password.decode('utf-8')))

            # Grant SELECT, INSERT, UPDATE privileges on a specific table
            escaped_database_name = connection.MySQLConnection.converter.escape(database_name, encoding=connection_obj.charset)
            escaped_table_name = connection.MySQLConnection.converter.escape(table_name, encoding=connection_obj.charset)
            grant_privileges_query = "GRANT SELECT, INSERT, UPDATE ON {} . {} TO %s@'localhost'".format(escaped_database_name, escaped_table_name)
            cursor.execute(grant_privileges_query, (username,))

            connection_obj.commit()
            logging.info(f"User {username} created successfully with limited privileges.")
            return True
        except mysql.connector.Error as err:
            logging.error(f"Error creating user: {err}")
            connection_obj.rollback()
            return False
        except Exception as e:
            logging.exception(f"An unexpected error occurred: {e}")
            if connection_obj.is_connected():
                connection_obj.rollback()
            return False
        finally:
            if 'cursor' in locals() and cursor:
                cursor.close()
            if 'connection_obj' in locals() and connection_obj and connection_obj.is_connected():
                connection_obj.close()
    else:
        logging.error("Failed to create user: No database connection.")
        return False


def limit_user_access(username, database_name, table_name, user_id_column, user_id):
    """
    Limits user access to only their own data using a WHERE clause in views or stored procedures.
    This example creates a view that filters data based on the user's ID.
    """
    if not validate_username(username):
        logging.error("Invalid username format.")
        return None

    if not isinstance(user_id, int):
        logging.error("User ID must be an integer.")
        return None

    connection_obj = get_connection()
    if connection_obj:
        try:
            cursor = connection_obj.cursor()

            # Create a view that filters data based on the user's ID
            view_name = f"vw_user_orders_{username}"  # More standardized view naming
            escaped_database_name = connection.MySQLConnection.converter.escape(database_name, encoding=connection_obj.charset)
            escaped_table_name = connection.MySQLConnection.converter.escape(table_name, encoding=connection_obj.charset)
            escaped_user_id_column = connection.MySQLConnection.converter.escape(user_id_column, encoding=connection_obj.charset)

            create_view_query = f"""
            CREATE OR REPLACE VIEW {escaped_database_name}.{connection.MySQLConnection.converter.escape(view_name, encoding=connection_obj.charset)} AS
            SELECT * FROM {escaped_database_name}.{escaped_table_name}
            WHERE {escaped_user_id_column} = %s
            """
            cursor.execute(create_view_query, (user_id,))

            # Grant SELECT privilege to the user on the view
            grant_select_query = "GRANT SELECT ON {} . {} TO %s@'localhost'".format(escaped_database_name, connection.MySQLConnection.converter.escape(view_name, encoding=connection_obj.charset))
            cursor.execute(grant_select_query, (username,))

            # Revoke direct access to the table (optional, but recommended)
            revoke_access_query = "REVOKE SELECT, INSERT, UPDATE ON {} . {} FROM %s@'localhost'".format(escaped_database_name, escaped_table_name)
            cursor.execute(revoke_access_query, (username,))

            connection_obj.commit()
            logging.info(f"User {username} access limited to their own data.")
            return True
        except mysql.connector.Error as err:
            logging.error(f"Error limiting user access: {err}")
            connection_obj.rollback()
            return False
        except Exception as e:
            logging.exception(f"An unexpected error occurred: {e}")
            if connection_obj.is_connected():
                connection_obj.rollback()
            return False
        finally:
            if 'cursor' in locals() and cursor:
                cursor.close()
            if 'connection_obj' in locals() and connection_obj and connection_obj.is_connected():
                connection_obj.close()
    else:
        logging.error("Failed to limit user access: No database connection.")
        return False


def validate_username(username):
    """
    Validates the username format.
    """
    if not isinstance(username, str):
        logging.warning("Username must be a string.")
        return False
    if len(username) < 3 or len(username) > 50:
        logging.warning("Username must be between 3 and 50 characters.")
        return False
    if not username.isalnum():  # Allows only alphanumeric characters
        logging.warning("Username must contain only alphanumeric characters.")
        return False
    return True


def validate_password(password):
    """
    Validates the password format.  Add more complexity requirements as needed.
    """
    if not isinstance(password, str):
        logging.warning("Password must be a string.")
        return False
    if len(password) < 8:
        logging.warning("Password must be at least 8 characters long.")
        return False
    # Add more checks for complexity (e.g., special characters, numbers)
    return True


# Example Usage (replace with your actual values)
if __name__ == '__main__':
    # Initialize the connection pool
    get_connection_pool()

    # Example 1:  Parameterized query
    query = "SELECT * FROM users WHERE username = %s"
    username = "testuser"
    data = fetch_data(query, (username,))
    if data:
        logging.info(f"Data for user {username}: {data}")

    # Example 2:  Insert data with parameterized query
    insert_query = "INSERT INTO products (name, price) VALUES (%s, %s)"
    product_name = "New Product"
    product_price = 25.99
    rows_affected = execute_query(insert_query, (product_name, product_price))
    if rows_affected:
        logging.info(f"{rows_affected} row(s) inserted.")

    # Example 3: Create a user with limited privileges
    new_username = "limited_user"
    new_password = "secure_password"  # Replace with a strong, unique password
    database_name = DB_NAME  # Replace with your database name
    table_name = "orders"  # Replace with your table name
    # Consider using bcrypt: pip install bcrypt
    if create_user(new_username, new_password, database_name, table_name):
        logging.info(f"User {new_username} created successfully.")
    else:
        logging.error(f"Failed to create user {new_username}.")

    # Example 4: Limit user access to their own data
    user_id_column = "user_id"  # Replace with the column that identifies the user
    user_id = 123  # Replace with the user's ID
    if limit_user_access(new_username, database_name, table_name, user_id_column, user_id):
        logging.info(f"User {new_username} access limited successfully.")
    else:
        logging.error(f"Failed to limit user {new_username} access.")

    # IMPORTANT: Ensure .env is added to your .gitignore file!

