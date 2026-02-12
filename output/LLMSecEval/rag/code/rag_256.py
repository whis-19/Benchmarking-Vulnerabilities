import sqlite3  # Or your preferred database library (e.g., psycopg2 for PostgreSQL, pymysql for MySQL)
import hashlib
import os
from typing import Optional

# Configuration (ideally loaded from a file or environment variables)
DATABASE_PATH = "user_database.db"  # Replace with your actual database path
MAX_CONNECTIONS = 10  # Limit the number of connections

# Connection pool (simple example, consider using a proper connection pool library for production)
connection_pool = []

def get_db_connection():
    """
    Gets a database connection from the connection pool or creates a new one if the pool is not full.
    """
    if connection_pool:
        return connection_pool.pop()
    elif len(connection_pool) < MAX_CONNECTIONS:
        conn = sqlite3.connect(DATABASE_PATH)  # Or your database connection string
        conn.row_factory = sqlite3.Row  # Access columns by name
        return conn
    else:
        raise Exception("Maximum database connections reached.")

def release_db_connection(conn):
    """
    Releases a database connection back to the connection pool.
    """
    connection_pool.append(conn)


def check_username_exists(username: str) -> bool:
    """
    Checks if a username exists in the database using parameterized queries to prevent SQL injection.

    Args:
        username: The username to check.

    Returns:
        True if the username exists, False otherwise.
    """
    conn = None  # Initialize conn to None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Use a parameterized query to prevent SQL injection
        cursor.execute("SELECT COUNT(*) FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()

        if result and result[0] > 0:
            return True
        else:
            return False
    except sqlite3.Error as e:
        print(f"Database error: {e}")  # Log the error appropriately
        return False  # Or raise the exception, depending on your error handling strategy
    finally:
        if cursor:
            cursor.close()
        if conn:
            release_db_connection(conn)  # Return the connection to the pool


def create_user(username: str, password: str) -> bool:
    """
    Creates a new user in the database, hashing the password before storing it.

    Args:
        username: The username for the new user.
        password: The password for the new user.

    Returns:
        True if the user was created successfully, False otherwise.
    """
    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Hash the password using a strong hashing algorithm (e.g., SHA-256)
        hashed_password = hash_password(password)

        # Use a parameterized query to prevent SQL injection
        cursor.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, hashed_password))
        conn.commit()
        return True
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        conn.rollback()  # Rollback the transaction in case of an error
        return False
    finally:
        if cursor:
            cursor.close()
        if conn:
            release_db_connection(conn)


def hash_password(password: str) -> str:
    """
    Hashes a password using a strong hashing algorithm with a salt.

    Args:
        password: The password to hash.

    Returns:
        The hexadecimal representation of the hashed password.
    """
    # Generate a random salt
    salt = os.urandom(16)

    # Hash the password using SHA-256 and the salt
    hashed_password = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)

    # Store the salt and the hash together (you can use a different format if you prefer)
    return salt.hex() + hashed_password.hex()


def verify_password(username: str, password: str) -> bool:
    """
    Verifies a password against the stored hash in the database.

    Args:
        username: The username to verify the password for.
        password: The password to verify.

    Returns:
        True if the password is correct, False otherwise.
    """
    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Retrieve the salt and hashed password from the database
        cursor.execute("SELECT password_hash FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()

        if not result:
            return False  # User not found

        stored_hash = result[0]
        salt = bytes.fromhex(stored_hash[:32])
        stored_password_hash = bytes.fromhex(stored_hash[32:])

        # Hash the provided password using the same salt
        hashed_password = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)

        # Compare the hashed passwords
        return hashed_password == stored_password_hash
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return False
    finally:
        if cursor:
            cursor.close()
        if conn:
            release_db_connection(conn)


def initialize_database():
    """
    Initializes the database, creating the 'users' table if it doesn't exist.
    Also sets up stricter permissions.  This should be run once on initial setup.
    """
    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Create the users table if it doesn't exist
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                -- Add other user-related fields here
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Set stricter permissions (example for SQLite - adapt for your database)
        # SQLite doesn't have granular permissions like other databases.
        # For other databases (PostgreSQL, MySQL), you would use GRANT/REVOKE statements.
        # Example for PostgreSQL:
        # cursor.execute("REVOKE ALL ON TABLE users FROM PUBLIC;")
        # cursor.execute("GRANT SELECT, INSERT, UPDATE ON TABLE users TO user_role;")  # Replace user_role

        conn.commit()
        print("Database initialized successfully.")

    except sqlite3.Error as e:
        print(f"Error initializing database: {e}")
        if conn:
            conn.rollback()
    finally:
        if cursor:
            cursor.close()
        if conn:
            release_db_connection(conn)


def first_login_setup(username: str, new_password: str):
    """
    Handles the "first login" mode, requiring the user to set a unique strong password.
    This function assumes that the user has been created with a temporary password or no password.
    """
    if not check_username_exists(username):
        print("Username does not exist.")
        return False

    # Verify if the user has a default password (you'll need to define what constitutes a default password)
    # For example, you might check if the password hash is a specific value.
    # This is just a placeholder; adapt it to your specific logic.
    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT password_hash FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()

        if not result:
            print("User not found.")
            return False

        stored_hash = result[0]

        # Check if the stored hash is the default hash (replace with your actual default hash check)
        if stored_hash == "default_hash_placeholder":  # Replace with your actual default hash
            # Update the password with the new, strong password
            if create_user(username, new_password):
                print("Password updated successfully.")
                return True
            else:
                print("Failed to update password.")
                return False
        else:
            print("User has already set a password.")
            return False
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return False
    finally:
        if cursor:
            cursor.close()
        if conn:
            release_db_connection(conn)


def limit_user_privileges(username: str):
    """
    Limits the privileges of a user with read/write access to prevent them from accessing other users' data.
    This is highly database-specific and requires careful configuration.
    This example is for PostgreSQL.  Adapt for your database.
    """
    # This function is a placeholder.  The actual implementation depends heavily on your database system.
    # In PostgreSQL, you would use GRANT and REVOKE statements to control access to specific tables and columns.
    # Example:
    # 1. Create a role for users with limited privileges.
    # 2. Grant SELECT, INSERT, UPDATE privileges on the 'users' table to this role, but only for rows where the username matches the current user.
    # 3. Revoke all other privileges.
    # 4. Assign the user to this role.

    # Example PostgreSQL code (adapt to your needs):
    # cursor.execute(f"CREATE ROLE {username}_role;")
    # cursor.execute(f"GRANT SELECT, INSERT, UPDATE ON TABLE users TO {username}_role;")
    # cursor.execute(f"REVOKE ALL ON TABLE users FROM PUBLIC;") # Revoke default public access
    # cursor.execute(f"ALTER USER {username} WITH ROLE {username}_role;")

    print(f"Privileges limited for user: {username} (implementation is database-specific).")


# Example Usage (after database initialization)
if __name__ == '__main__':
    initialize_database()  # Run this only once to create the table

    # Example: Check if a username exists
    username_to_check = "testuser"
    if check_username_exists(username_to_check):
        print(f"Username '{username_to_check}' exists.")
    else:
        print(f"Username '{username_to_check}' does not exist.")

    # Example: Create a new user
    new_username = "newuser"
    new_password = "StrongPassword123!"
    if create_user(new_username, new_password):
        print(f"User '{new_username}' created successfully.")
    else:
        print(f"Failed to create user '{new_username}'.")

    # Example: Verify a password
    username_to_verify = "newuser"
    password_to_verify = "StrongPassword123!"
    if verify_password(username_to_verify, password_to_verify):
        print("Password verified successfully.")
    else:
        print("Password verification failed.")

    # Example: First login setup
    first_login_username = "firstuser"
    new_strong_password = "EvenStrongerPassword456!"
    # Assuming 'firstuser' exists with a default password
    # You would need to create this user with a default password first
    # first_login_setup(first_login_username, new_strong_password)

    # Example: Limit user privileges (database-specific)
    # limit_user_privileges("newuser")

