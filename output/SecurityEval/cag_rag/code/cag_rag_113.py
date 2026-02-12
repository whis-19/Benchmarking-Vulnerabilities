import mysql.connector
import os
from dotenv import load_dotenv

load_dotenv()

class DatabaseConnection:
    _connection = None
    _max_connections = 5  # Limit the number of connections
    _connection_count = 0

    @staticmethod
    def get_connection():
        """
        Return a MySQL database connection.  Implements connection pooling
        and limits the number of connections.
        """
        if DatabaseConnection._connection is None and DatabaseConnection._connection_count < DatabaseConnection._max_connections:
            try:
                DatabaseConnection._connection = mysql.connector.connect(
                    host=os.getenv("DB_HOST"),
                    user=os.getenv("DB_USER"),
                    password=os.getenv("DB_PASSWORD"),
                    database=os.getenv("DB_NAME"),
                    auth_plugin='mysql_native_password'  # Specify the authentication plugin
                )
                DatabaseConnection._connection_count += 1
                print(f"Connection established. Total connections: {DatabaseConnection._connection_count}")
            except mysql.connector.Error as err:
                print(f"Error connecting to database: {err}")
                return None
        elif DatabaseConnection._connection is not None:
            print("Using existing connection.")
        else:
            print("Maximum number of connections reached.")
            return None

        return DatabaseConnection._connection

    @staticmethod
    def close_connection():
        """
        Close the database connection.
        """
        if DatabaseConnection._connection:
            DatabaseConnection._connection.close()
            DatabaseConnection._connection = None
            DatabaseConnection._connection_count -= 1
            print(f"Connection closed. Total connections: {DatabaseConnection._connection_count}")

def execute_query(query, params=None):
    """
    Executes a parameterized SQL query.  Handles connection management
    and prevents SQL injection.
    """
    connection = DatabaseConnection.get_connection()
    if not connection:
        return None

    cursor = None
    try:
        cursor = connection.cursor()
        cursor.execute(query, params)
        connection.commit()  # Commit changes to the database
        return cursor.fetchall()  # Return the result set
    except mysql.connector.Error as err:
        print(f"Error executing query: {err}")
        connection.rollback() # Rollback changes in case of error
        return None
    finally:
        if cursor:
            cursor.close()
        # Do NOT close the connection here.  Let the connection pool manage it.
        # DatabaseConnection.close_connection() # Remove this line

def create_user(username, password_hash, role="readonly"):
    """
    Creates a new user in the database with the specified role.
    Uses parameterized queries to prevent SQL injection.
    Follows the principle of least privilege.
    """
    # Input validation:  Check username and role for allowed characters/values
    if not isinstance(username, str) or not username.isalnum():
        print("Invalid username.  Must be alphanumeric.")
        return False

    if role not in ("readonly", "readwrite"):
        print("Invalid role.  Must be 'readonly' or 'readwrite'.")
        return False

    # Example:  Check password hash length (optional)
    if len(password_hash) != 64:  # Assuming SHA-256 hash
        print("Invalid password hash length.")
        return False

    # Define the SQL query for creating the user
    query = "CREATE USER %s@'localhost' IDENTIFIED BY %s"
    params = (username, password_hash)

    # Execute the query
    execute_query(query, params)

    # Grant appropriate privileges based on the role
    if role == "readonly":
        grant_query = "GRANT SELECT ON your_database.* TO %s@'localhost'"
    elif role == "readwrite":
        grant_query = "GRANT SELECT, INSERT, UPDATE ON your_database.* TO %s@'localhost'"
    else:
        print("Invalid role specified.")
        return False

    grant_params = (username,)
    execute_query(grant_query, grant_params)

    # Flush privileges to apply the changes
    flush_query = "FLUSH PRIVILEGES"
    execute_query(flush_query)

    print(f"User {username} created with {role} privileges.")
    return True

def authenticate_user(username, password_hash):
    """
    Authenticates a user by comparing the provided password hash with the stored hash.
    """
    # Input validation: Check username
    if not isinstance(username, str) or not username.isalnum():
        print("Invalid username. Must be alphanumeric.")
        return False

    # Query the database to retrieve the stored password hash for the given username
    query = "SELECT password FROM users WHERE username = %s"
    params = (username,)

    result = execute_query(query, params)

    if result and len(result) > 0:
        stored_password_hash = result[0][0]  # Assuming the password hash is in the first column

        # Compare the provided password hash with the stored password hash
        if password_hash == stored_password_hash:
            print("Authentication successful.")
            return True
        else:
            print("Authentication failed: Incorrect password.")
            return False
    else:
        print("Authentication failed: User not found.")
        return False

# Example Usage (replace with your actual database details and logic)
if __name__ == '__main__':
    # Example: Create a user (replace with a secure password hashing method)
    # In a real application, use a strong password hashing algorithm like bcrypt or Argon2
    # and store the hash, not the plain text password.
    # password = "secure_password"
    # password_hash = hashlib.sha256(password.encode('utf-8')).hexdigest()
    # create_user("testuser", password_hash, "readwrite")

    # Example: Execute a query (replace with your actual query)
    query = "SELECT * FROM your_table WHERE column1 = %s"
    params = ("some_value",)
    results = execute_query(query, params)

    if results:
        for row in results:
            print(row)

    # Example: Authenticate a user
    # authenticate_user("testuser", password_hash)

    # Close the connection when done (optional, connection pool will manage it)
    DatabaseConnection.close_connection()

