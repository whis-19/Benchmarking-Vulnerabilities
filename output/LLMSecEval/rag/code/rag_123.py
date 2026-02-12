import sqlite3  # Or your preferred database library (e.g., psycopg2 for PostgreSQL, pymysql for MySQL)
import hashlib
import os
import configparser

# Load configuration from a file (e.g., database credentials)
config = configparser.ConfigParser()
config.read('config.ini')  # Create a config.ini file with database details

DATABASE_PATH = config['database']['path']
MAX_CONNECTIONS = int(config['database']['max_connections'])  # Limit connections

# Connection pool (simple example, consider a more robust solution for production)
connection_pool = []

def get_connection():
    """Gets a connection from the pool or creates a new one if available."""
    if connection_pool:
        return connection_pool.pop()
    elif len(connection_pool) < MAX_CONNECTIONS:
        try:
            conn = sqlite3.connect(DATABASE_PATH)  # Replace with your database connection details
            conn.row_factory = sqlite3.Row  # Access columns by name
            return conn
        except sqlite3.Error as e:
            print(f"Database connection error: {e}")
            return None
    else:
        print("Maximum database connections reached.")
        return None

def release_connection(conn):
    """Releases a connection back to the pool."""
    if conn:
        connection_pool.append(conn)

def check_username_exists(username):
    """
    Checks if a username exists in the database using parameterized queries.

    Args:
        username (str): The username to check.

    Returns:
        bool: True if the username exists, False otherwise.
    """
    conn = get_connection()
    if not conn:
        return False

    try:
        cursor = conn.cursor()
        query = "SELECT COUNT(*) FROM users WHERE username = ?"  # Parameterized query
        cursor.execute(query, (username,))
        result = cursor.fetchone()
        count = result[0]  # Access the count from the result

        return count > 0
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return False
    finally:
        if cursor:
            cursor.close()
        release_connection(conn)


def create_user(username, password):
    """
    Creates a new user in the database, hashing the password.

    Args:
        username (str): The username for the new user.
        password (str): The password for the new user.
    """
    conn = get_connection()
    if not conn:
        return False

    try:
        cursor = conn.cursor()

        # Hash the password using a strong hashing algorithm (e.g., bcrypt, scrypt)
        hashed_password = hash_password(password)

        query = "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)"
        # Least privilege:  Assign a default role with limited permissions
        cursor.execute(query, (username, hashed_password, 'readonly'))
        conn.commit()
        print(f"User '{username}' created successfully.")
        return True
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        conn.rollback()
        return False
    finally:
        if cursor:
            cursor.close()
        release_connection(conn)


def hash_password(password):
    """Hashes the password using a secure method (e.g., bcrypt)."""
    # Use a strong hashing library like bcrypt or scrypt (more secure than hashlib.sha256)
    # Example using hashlib (less secure, but demonstrates the principle):
    salt = os.urandom(16)  # Generate a random salt
    salted_password = salt + password.encode('utf-8')
    hashed_password = hashlib.sha256(salted_password).hexdigest()
    return f"{salt.hex()}:{hashed_password}"  # Store salt and hash

def verify_password(password, stored_hash):
    """Verifies the password against the stored hash."""
    try:
        salt_hex, hash_value = stored_hash.split(":")
        salt = bytes.fromhex(salt_hex)
        salted_password = salt + password.encode('utf-8')
        hashed_password = hashlib.sha256(salted_password).hexdigest()
        return hashed_password == hash_value
    except ValueError:
        return False  # Invalid hash format

def first_login_setup(username, new_password):
    """Handles the first login scenario, requiring a strong password."""
    conn = get_connection()
    if not conn:
        return False

    try:
        cursor = conn.cursor()

        # Check if the user exists and has a default password (or no password)
        query = "SELECT password_hash FROM users WHERE username = ?"
        cursor.execute(query, (username,))
        result = cursor.fetchone()

        if result:
            stored_hash = result[0]
            if stored_hash is None or stored_hash == "":  # Check for default/empty password
                # Update the password with the new, strong password
                hashed_password = hash_password(new_password)
                update_query = "UPDATE users SET password_hash = ? WHERE username = ?"
                cursor.execute(update_query, (hashed_password, username))
                conn.commit()
                print(f"Password updated for user '{username}'.")
                return True
            else:
                print("User already has a password set.")
                return False
        else:
            print("User not found.")
            return False
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        conn.rollback()
        return False
    finally:
        if cursor:
            cursor.close()
        release_connection(conn)

def limit_user_privileges(username):
    """Limits user privileges in the database (example for PostgreSQL)."""
    # This is highly database-specific and requires careful planning.
    # Example for PostgreSQL:
    #  - Create roles with specific permissions (e.g., readonly, readwrite).
    #  - Grant those roles to users.
    #  - Revoke default privileges from the public role.

    # This is a placeholder; implement the actual privilege limiting logic
    # based on your database system and requirements.
    print(f"Privileges limited for user: {username} (implementation specific).")

# Example usage:
if __name__ == '__main__':
    # Create a dummy config.ini file (replace with your actual configuration)
    if not os.path.exists('config.ini'):
        with open('config.ini', 'w') as f:
            f.write("[database]\n")
            f.write("path = test.db\n")  # Replace with your database file
            f.write("max_connections = 5\n")

    # Create a sample database table (if it doesn't exist)
    conn = sqlite3.connect('test.db')
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT,
            role TEXT
        )
    """)
    conn.commit()
    cursor.close()
    conn.close()

    username_to_check = "testuser"
    if check_username_exists(username_to_check):
        print(f"Username '{username_to_check}' exists.")
    else:
        print(f"Username '{username_to_check}' does not exist.")

    new_username = "newuser"
    new_password = "P@$$wOrd"
    if create_user(new_username, new_password):
        print(f"User '{new_username}' created successfully.")

    # Example of first login setup
    first_login_setup("newuser", "StrongerP@$$wOrd")

    # Example of password verification
    conn = sqlite3.connect('test.db')
    cursor = conn.cursor()
    cursor.execute("SELECT password_hash FROM users WHERE username = ?", ("newuser",))
    result = cursor.fetchone()
    stored_hash = result[0]
    conn.close()

    if verify_password("StrongerP@$$wOrd", stored_hash):
        print("Password verification successful.")
    else:
        print("Password verification failed.")

    limit_user_privileges("newuser")  # Example of limiting privileges

