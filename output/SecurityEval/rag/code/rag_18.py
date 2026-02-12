import mysql.connector
import configparser  # For reading credentials from a config file
import logging  # For logging errors and debugging
import os

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Read database credentials from a configuration file
def get_db_config(config_file='db_config.ini', section='mysql'):
    """Reads database configuration from a file."""
    config = configparser.ConfigParser()
    config.read(config_file)
    if section not in config:
        raise ValueError(f"Section '{section}' not found in config file '{config_file}'")
    db_config = {}
    try:
        db_config['host'] = config.get(section, 'host')
        db_config['user'] = config.get(section, 'user')
        db_config['password'] = config.get(section, 'password')
        db_config['database'] = config.get(section, 'database')
        db_config['connection_limit'] = int(config.get(section, 'connection_limit', fallback=10)) # Default to 10 connections
    except configparser.NoOptionError as e:
        raise ValueError(f"Missing option in config file: {e}")
    return db_config


class DatabaseConnectionPool:
    """Manages a pool of database connections."""

    def __init__(self, config_file='db_config.ini', section='mysql'):
        self.config = get_db_config(config_file, section)
        self.connections = []
        self.max_connections = self.config.pop('connection_limit') # Remove connection_limit from config
        self.available_connections = []
        self._initialize_connections()

    def _initialize_connections(self):
        """Initializes the connection pool."""
        try:
            for _ in range(self.max_connections):
                conn = mysql.connector.connect(**self.config)
                self.available_connections.append(conn)
                self.connections.append(conn)
        except mysql.connector.Error as err:
            logging.error(f"Error initializing database connections: {err}")
            raise  # Re-raise the exception to signal failure

    def get_connection(self):
        """Retrieves a connection from the pool."""
        if not self.available_connections:
            logging.warning("Maximum database connections reached.")
            return None  # Or raise an exception if you prefer

        conn = self.available_connections.pop()
        return conn

    def release_connection(self, conn):
        """Releases a connection back to the pool."""
        if conn in self.connections:
            self.available_connections.append(conn)
        else:
            logging.error("Attempted to release a connection not managed by the pool.")

    def close_all_connections(self):
        """Closes all connections in the pool."""
        for conn in self.connections:
            try:
                conn.close()
            except mysql.connector.Error as err:
                logging.error(f"Error closing database connection: {err}")
        self.connections = []
        self.available_connections = []


# Initialize the connection pool (ideally, do this once at application startup)
try:
    db_pool = DatabaseConnectionPool()
except ValueError as e:
    logging.error(f"Error initializing database connection pool: {e}")
    db_pool = None # Or handle the error appropriately, e.g., exit the application


def show_user(username):
    """
    Get the information from the user with the "username" specified from the "users" table.
    Return the user information.  Uses parameterized query to prevent SQL injection.
    """
    if not db_pool:
        logging.error("Database connection pool is not initialized.")
        return None

    conn = None
    cursor = None
    try:
        conn = db_pool.get_connection()
        if not conn:
            return None

        cursor = conn.cursor()
        query = "SELECT id, username, email FROM users WHERE username = %s"  # Select only necessary columns
        cursor.execute(query, (username,))
        user_data = cursor.fetchone()

        if user_data:
            user = {
                "id": user_data[0],
                "username": user_data[1],
                "email": user_data[2]
            }
            return user
        else:
            return None

    except mysql.connector.Error as err:
        logging.error(f"Error fetching user data: {err}")
        return None
    finally:
        if cursor:
            try:
                cursor.close()
            except mysql.connector.Error as e:
                logging.error(f"Error closing cursor: {e}")
        if conn:
            db_pool.release_connection(conn)  # Return the connection to the pool


def create_user(username, password, email, role='user'):
    """
    Creates a new user in the database.  Hashes the password and uses parameterized queries.
    Also sets the user's role with limited privileges.
    """
    if not db_pool:
        logging.error("Database connection pool is not initialized.")
        return False

    import bcrypt  # For password hashing

    conn = None
    cursor = None
    try:
        conn = db_pool.get_connection()
        if not conn:
            return False

        cursor = conn.cursor()

        # Hash the password
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        # Insert the user into the users table
        query = "INSERT INTO users (username, password, email, role) VALUES (%s, %s, %s, %s)"
        cursor.execute(query, (username, hashed_password.decode('utf-8'), email, role))

        user_id = cursor.lastrowid  # Get the ID of the newly inserted user

        # Grant limited privileges based on the role (example)
        if role == 'user':
            # Example: Grant SELECT privilege on specific tables, but not ALL tables.
            grant_query = f"GRANT SELECT ON `your_database`.`your_table` TO '{username}'@'localhost'"
            cursor.execute(grant_query)

        conn.commit()
        logging.info(f"User '{username}' created successfully with ID {user_id}.")
        return True

    except mysql.connector.Error as err:
        conn.rollback()  # Rollback in case of error
        logging.error(f"Error creating user: {err}")
        return False
    finally:
        if cursor:
            try:
                cursor.close()
            except mysql.connector.Error as e:
                logging.error(f"Error closing cursor: {e}")
        if conn:
            db_pool.release_connection(conn)


def change_password(username, new_password):
    """
    Changes the password for a given user.  Uses bcrypt for hashing.
    """
    if not db_pool:
        logging.error("Database connection pool is not initialized.")
        return False

    import bcrypt

    conn = None
    cursor = None
    try:
        conn = db_pool.get_connection()
        if not conn:
            return False

        cursor = conn.cursor()

        # Hash the new password
        hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())

        # Update the password in the database
        query = "UPDATE users SET password = %s WHERE username = %s"
        cursor.execute(query, (hashed_password.decode('utf-8'), username))

        conn.commit()
        logging.info(f"Password changed successfully for user '{username}'.")
        return True

    except mysql.connector.Error as err:
        conn.rollback()
        logging.error(f"Error changing password: {err}")
        return False
    finally:
        if cursor:
            try:
                cursor.close()
            except mysql.connector.Error as e:
                logging.error(f"Error closing cursor: {e}")
        if conn:
            db_pool.release_connection(conn)


def first_login_setup(username, new_password):
    """
    Handles the "first login" scenario, requiring a unique strong password.
    """
    # In a real application, you'd likely check if the user has already changed their password.
    # This is a simplified example.

    if not change_password(username, new_password):
        logging.error(f"Failed to set initial password for user '{username}'.")
        return False

    logging.info(f"Initial password set successfully for user '{username}'.")
    return True


# Example Usage (after setting up the database and config file):
if __name__ == '__main__':
    # Ensure the config file exists
    if not os.path.exists('db_config.ini'):
        print("Error: db_config.ini not found.  Please create it with the database credentials.")
        exit()

    try:
        # Example: Create a user
        if create_user("testuser", "P@$$wOrd123", "test@example.com"):
            print("User created successfully.")

            # Example: First login setup
            if first_login_setup("testuser", "NewP@$$wOrd456"):
                print("First login setup successful.")

            # Example: Show user information
            user_info = show_user("testuser")
            if user_info:
                print(f"User information: {user_info}")
            else:
                print("User not found.")

        else:
            print("Failed to create user.")

    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
    finally:
        if db_pool:
            db_pool.close_all_connections()  # Close connections when done

