import logging
import sqlite3  # Using sqlite3 for demonstration, consider a more robust DB in production
import os

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Placeholder for user authentication (replace with a secure implementation)
def isAuthorizedUser(userId):
    """
    Placeholder for user authentication.  In a real application, this would
    verify the user's credentials against a secure store (e.g., hashed password
    in a database).
    """
    # Replace this with actual authentication logic
    # Example: Check if the user exists in a database and the password is correct
    # using bcrypt or similar.
    # For demonstration purposes, we'll just allow user IDs 1-10.
    return 1 <= userId <= 10


def getUserBankAccount(userId, connection):
    """
    Retrieves bank account information for a user from the database.

    Args:
        userId (int): The ID of the user.
        connection (sqlite3.Connection): The database connection object.

    Returns:
        dict: A dictionary containing the user's bank account information,
              or None if the user is not authorized or the account is not found.

    Raises:
        Exception: If there is an error retrieving the result from the database.
    """

    if not isinstance(userId, int):
        logging.error("Invalid userId: %s.  Must be an integer.", userId)
        raise ValueError("userId must be an integer.")

    if not isinstance(connection, sqlite3.Connection):
        logging.error("Invalid connection object provided.")
        raise TypeError("connection must be a sqlite3.Connection object.")

    if not isAuthorizedUser(userId):
        logging.warning("Unauthorized access attempt for userId: %s", userId)
        return None  # Or raise an exception if unauthorized access should be an error

    try:
        cursor = connection.cursor()
        # Use a parameterized query to prevent SQL injection
        query = "SELECT account_number, balance FROM accounts WHERE user_id = ?"
        cursor.execute(query, (userId,))  # Pass userId as a tuple

        result = cursor.fetchone()

        if result:
            account_info = {
                "account_number": result[0],
                "balance": result[1]
            }
            logging.info("Successfully retrieved account information for userId: %s", userId)
            return account_info
        else:
            logging.warning("No account found for userId: %s", userId)
            return None  # Or raise an exception if account not found is an error

    except sqlite3.Error as e:
        logging.exception("Error retrieving account information for userId: %s", userId)
        raise Exception(f"Error retrieving account information: {e}")


def create_user_account(username, password, connection):
    """
    Creates a new user account in the database.  This function demonstrates
    secure password hashing and parameterized queries.

    Args:
        username (str): The username for the new account.
        password (str): The password for the new account.
        connection (sqlite3.Connection): The database connection object.

    Raises:
        Exception: If there is an error creating the user account.
    """
    import bcrypt  # Import bcrypt here to avoid unnecessary dependency if not used

    if not isinstance(username, str) or not username:
        raise ValueError("Username must be a non-empty string.")
    if not isinstance(password, str) or not password:
        raise ValueError("Password must be a non-empty string.")
    if not isinstance(connection, sqlite3.Connection):
        raise TypeError("connection must be a sqlite3.Connection object.")

    try:
        # Hash the password using bcrypt
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        cursor = connection.cursor()
        # Use a parameterized query to prevent SQL injection
        query = "INSERT INTO users (username, password_hash) VALUES (?, ?)"
        cursor.execute(query, (username, hashed_password.decode('utf-8')))  # Store hash as string
        connection.commit()
        logging.info("Successfully created user account: %s", username)

    except sqlite3.Error as e:
        logging.exception("Error creating user account: %s", username)
        connection.rollback()  # Rollback in case of error
        raise Exception(f"Error creating user account: {e}")


def authenticate_user(username, password, connection):
    """
    Authenticates a user by comparing the provided password with the stored hash.

    Args:
        username (str): The username to authenticate.
        password (str): The password to check.
        connection (sqlite3.Connection): The database connection object.

    Returns:
        bool: True if the authentication is successful, False otherwise.
    """
    import bcrypt

    if not isinstance(username, str) or not username:
        raise ValueError("Username must be a non-empty string.")
    if not isinstance(password, str) or not password:
        raise ValueError("Password must be a non-empty string.")
    if not isinstance(connection, sqlite3.Connection):
        raise TypeError("connection must be a sqlite3.Connection object.")

    try:
        cursor = connection.cursor()
        query = "SELECT password_hash FROM users WHERE username = ?"
        cursor.execute(query, (username,))
        result = cursor.fetchone()

        if result:
            hashed_password = result[0].encode('utf-8')  # Get hash from DB and encode
            if bcrypt.checkpw(password.encode('utf-8'), hashed_password):
                logging.info("User %s successfully authenticated.", username)
                return True
            else:
                logging.warning("Authentication failed for user: %s (incorrect password)", username)
                return False
        else:
            logging.warning("Authentication failed for user: %s (user not found)", username)
            return False

    except sqlite3.Error as e:
        logging.exception("Error during authentication for user: %s", username)
        raise Exception(f"Error during authentication: {e}")


def initialize_database(db_path):
    """
    Initializes the database with the necessary tables (users and accounts).

    Args:
        db_path (str): The path to the SQLite database file.
    """
    try:
        connection = sqlite3.connect(db_path)
        cursor = connection.cursor()

        # Create the users table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                user_id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL
            )
        """)

        # Create the accounts table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS accounts (
                account_id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                account_number TEXT UNIQUE NOT NULL,
                balance REAL NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(user_id)
            )
        """)

        connection.commit()
        logging.info("Database initialized successfully.")

    except sqlite3.Error as e:
        logging.exception("Error initializing database.")
        raise Exception(f"Error initializing database: {e}")
    finally:
        if connection:
            connection.close()


if __name__ == '__main__':
    # Example Usage (replace with your actual database and user management)
    db_file = "bank.db"  # Database file name
    initialize_database(db_file)

    try:
        # Connect to the database
        connection = sqlite3.connect(db_file)

        # Example: Create a user account
        try:
            create_user_account("testuser", "securepassword", connection)
        except Exception as e:
            logging.error(f"Error creating user: {e}")

        # Example: Authenticate a user
        if authenticate_user("testuser", "securepassword", connection):
            logging.info("User authenticated successfully.")
        else:
            logging.warning("User authentication failed.")

        # Example: Get bank account information
        user_id = 1  # Replace with the actual user ID
        account_info = getUserBankAccount(user_id, connection)

        if account_info:
            print(f"Account Number: {account_info['account_number']}")
            print(f"Balance: {account_info['balance']}")
        else:
            print("Account information not found.")

    except Exception as e:
        logging.error(f"An error occurred: {e}")

    finally:
        if connection:
            connection.close()

