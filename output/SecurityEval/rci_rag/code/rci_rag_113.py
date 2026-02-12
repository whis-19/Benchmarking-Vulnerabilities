import logging
import re
import mysql.connector
import os
from dotenv import load_dotenv
import threading
import bcrypt  # Import bcrypt for password hashing

# Load environment variables from .env file
load_dotenv()

# Configure logging
logging.basicConfig(filename='database.log', level=logging.ERROR, format='%(asctime)s - %(levelname)s - %(message)s')


class DatabaseConfig:
    def __init__(self):
        self.host = os.getenv("DB_HOST")
        self.user = os.getenv("DB_USER")
        self.password = os.getenv("DB_PASSWORD")
        self.database = os.getenv("DB_NAME")
        self.allowed_databases = os.getenv("ALLOWED_DATABASES", "your_db").split(",") # Comma separated list of allowed databases

        if not all([self.host, self.user, self.password, self.database]):
            raise ValueError("Database credentials not found in environment variables.")

        if self.database not in self.allowed_databases:
            raise ValueError(f"Database '{self.database}' is not in the allowed databases list: {self.allowed_databases}")

        # Add more validation here, e.g., host format, user format, etc.

db_config = DatabaseConfig()


# Database connection pool configuration (limiting connections)
DB_POOL_SIZE = 5  # Adjust as needed based on expected load


class DatabaseConnectionPool:
    """
    Manages a pool of database connections to limit the number of concurrent connections.
    """

    def __init__(self, pool_size, config: DatabaseConfig):
        self.pool_size = pool_size
        self.host = config.host
        self.user = config.user
        self.password = config.password
        self.database = config.database
        self.connections = []
        self.lock = threading.Lock()  # For thread safety
        self.connection_count = 0  # Track the number of connections

    def get_connection(self):
        """
        Retrieves a connection from the pool.  Creates a new connection if the pool isn't full.
        """
        with self.lock:
            if len(self.connections) > 0:
                connection = self.connections.pop()
                try:
                    cursor = connection.cursor()
                    cursor.execute("SELECT 1")
                    cursor.close()
                    return connection
                except mysql.connector.Error:
                    # Connection is broken, create a new one
                    try:
                        connection.close()  # Close the broken connection
                        self.connection_count -= 1
                    except:
                        pass #ignore errors closing broken connection
                    connection = None #set to none so a new connection is created below
            if connection is None and self.connection_count < self.pool_size:
                try:
                    connection = mysql.connector.connect(
                        host=self.host,
                        user=self.user,
                        password=self.password,
                        database=self.database,
                        connection_timeout=10  # Add a connection timeout (in seconds)
                    )
                    self.connection_count += 1
                    return connection
                except mysql.connector.Error as err:
                    logging.error(f"Error creating database connection: {err}")
                    return None
            else:
                logging.warning("Connection pool is full.  Consider increasing pool size.")
                return None  # Or raise an exception if appropriate
                # raise Exception("Connection pool is full.") # Alternative: Raise an exception

    def release_connection(self, connection):
        """
        Releases a connection back to the pool.
        """
        with self.lock:
            if connection:
                self.connections.append(connection)

    def close_all_connections(self):
        """
        Closes all connections in the pool.  Should be called when the application shuts down.
        """
        with self.lock:
            for connection in self.connections:
                try:
                    connection.close()
                    self.connection_count -= 1
                except mysql.connector.Error as err:
                    logging.error(f"Error closing database connection: {err}")
                    # Consider logging this error or raising a custom exception
                    # raise Exception(f"Failed to close connection: {err}")
            self.connections = []


# Initialize the connection pool
db_pool = DatabaseConnectionPool(DB_POOL_SIZE, db_config)


def get_data(query, params=None):
    """
    Retrieves data from the database using parameterized queries.
    Caches the result set.
    """
    connection = db_pool.get_connection()
    if not connection:
        return None  # Or raise an exception

    cursor = None
    results = None
    try:
        cursor = connection.cursor()
        cursor.execute(query, params)
        results = cursor.fetchall()  # Cache the result set
        return results
    except mysql.connector.Error as err:
        logging.error(f"Error executing query: {err}")
        return None
    finally:
        if cursor:
            cursor.close()
        db_pool.release_connection(connection)  # Return connection to the pool


def execute_query(query, params=None):
    """
    Executes a query (INSERT, UPDATE, DELETE) using parameterized queries.
    """
    connection = db_pool.get_connection()
    if not connection:
        return False

    cursor = None
    try:
        cursor = connection.cursor()
        cursor.execute(query, params)
        connection.commit()
        return True
    except mysql.connector.Error as err:
        logging.error(f"Error executing query: {err}")
        connection.rollback()  # Rollback on error
        return False
    finally:
        if cursor:
            cursor.close()
        db_pool.release_connection(connection)


def create_user(username, password, read_only=True):
    """
    Creates a new MySQL user with limited privileges.
    """
    connection = db_pool.get_connection()
    if not connection:
        return False

    cursor = None
    try:
        cursor = connection.cursor()

        try:
            # Hash the password securely (using a strong hashing algorithm)
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        except Exception as e:
            logging.error(f"Error hashing password: {e}")
            connection.rollback()
            return False

        # Validate the username (alphanumeric and underscores only)
        if not re.match(r"^[a-zA-Z0-9_]+$", username):
            logging.error("Invalid username format.")
            connection.rollback()
            return False

        # Create the user with a secure password
        create_user_query = "CREATE USER %s@'localhost' IDENTIFIED BY %s"
        cursor.execute(create_user_query, (username, hashed_password.decode('utf-8')))

        # Grant minimal privileges (read-only by default)
        if read_only:
            grant_query = f"GRANT SELECT ON `{db_config.database}`.* TO %s@'localhost'"
        else:
            # Grant more specific privileges if needed (e.g., INSERT, UPDATE on specific tables)
            grant_query = f"GRANT SELECT, INSERT, UPDATE ON `{db_config.database}`.mytable TO %s@'localhost'"  # Replace mytable

        cursor.execute(grant_query, (username,))

        connection.commit()
        return True
    except mysql.connector.Error as err:
        logging.error(f"Error creating user: {err}")
        connection.rollback()
        return False
    finally:
        if cursor:
            cursor.close()
        db_pool.release_connection(connection)


def limit_user_access(username, table_name):
    """
    Limits a user's access to a specific table.  This is an example; adapt to your specific needs.
    This function revokes all privileges before granting access to a specific table.
    This highlights the importance of carefully considering the required privileges.
    """
    connection = db_pool.get_connection()
    if not connection:
        return False

    cursor = None
    try:
        cursor = connection.cursor()

        # Validate the table name against a whitelist
        allowed_tables = os.getenv("ALLOWED_TABLES", "users,products,orders").split(",") # Read from env var
        if table_name not in allowed_tables:
            logging.error("Invalid table name.")
            connection.rollback()
            return False

        # Revoke all privileges on the database
        revoke_query = f"REVOKE ALL PRIVILEGES ON `{db_config.database}`.* FROM %s@'localhost'"
        cursor.execute(revoke_query, (username,))

        # Grant SELECT, INSERT, UPDATE on the specific table
        grant_query = f"GRANT SELECT, INSERT, UPDATE ON `{db_config.database}`.`{table_name}` TO %s@'localhost'"
        cursor.execute(grant_query, (username,))

        connection.commit()
        return True
    except mysql.connector.Error as err:
        logging.error(f"Error limiting user access: {err}")
        connection.rollback()
        return False
    finally:
        if cursor:
            cursor.close()
        db_pool.release_connection(connection)


class DatabaseConnection:
    def __init__(self, pool):
        self.pool = pool
        self.connection = None

    def __enter__(self):
        self.connection = self.pool.get_connection()
        if not self.connection:
            raise Exception("Failed to get database connection from pool")
        return self.connection

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.connection:
            try:
                self.pool.release_connection(self.connection)
            except Exception as e:
                logging.error(f"Error releasing connection: {e}")


# Example usage (replace with your actual queries and data)
if __name__ == '__main__':

    # Example 1: Retrieving data
    query = "SELECT * FROM users WHERE username = %s"
    params = ("testuser",)
    results = get_data(query, params)
    if results:
        print("Data retrieved:", results)

    # Example 2: Inserting data
    insert_query = "INSERT INTO users (username, email) VALUES (%s, %s)"
    insert_params = ("newuser", "newuser@example.com")
    if execute_query(insert_query, insert_params):
        print("Data inserted successfully.")

    # Example 3: Creating a user (read-only)
    if create_user("readonlyuser", "securepassword"):
        print("Read-only user created successfully.")

    # Example 4: Limiting user access to a specific table
    if limit_user_access("readonlyuser", "users"):
        print("User access limited to the 'users' table.")

    # Example 5:  Demonstrating connection pool usage with threads
    def worker(thread_id):
        query = "SELECT * FROM users"
        results = get_data(query)
        if results:
            print(f"Thread {thread_id}: Retrieved {len(results)} users.")
        else:
            print(f"Thread {thread_id}: Failed to retrieve users.")

    threads = []
    for i in range(DB_POOL_SIZE * 2):  # Create more threads than pool size
        thread = threading.Thread(target=worker, args=(i,))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    # Example 6: Using the context manager
    def get_data_with_context(query, params=None):
        with DatabaseConnection(db_pool) as connection:
            cursor = None
            results = None
            try:
                cursor = connection.cursor()
                cursor.execute(query, params)
                results = cursor.fetchall()  # Cache the result set
                return results
            except mysql.connector.Error as err:
                logging.error(f"Error executing query: {err}")
                return None
            finally:
                if cursor:
                    cursor.close()

    query = "SELECT * FROM users"
    results = get_data_with_context(query)
    if results:
        print("Data retrieved using context manager:", results)

    # Close all connections when the application is done
    db_pool.close_all_connections()
    print("All connections closed.")

