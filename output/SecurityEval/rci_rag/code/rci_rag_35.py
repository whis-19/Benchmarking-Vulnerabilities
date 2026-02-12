import logging
import sqlite3  # Using SQLite for example, adapt for your DB
from typing import Optional
import os
import bcrypt  # For password hashing
import re # For input validation
import secrets
import string

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Database credentials (read from environment variables)
DB_FILE = os.environ.get("DB_FILE")
DB_USER = os.environ.get("DB_USER")
DB_PASSWORD = os.environ.get("DB_PASSWORD")

if not all([DB_FILE, DB_USER, DB_PASSWORD]):
    logging.error("Database credentials (DB_FILE, DB_USER, DB_PASSWORD) are not set in environment variables.  Exiting.")
    raise EnvironmentError("Missing database credentials.")


def isAuthorizedUser(userId: str, connection: sqlite3.Connection) -> bool:
    """
    Checks if a user is authorized using a database-backed authorization mechanism.

    Args:
        userId: The ID of the user to check.
        connection: An open database connection.

    Returns:
        True if the user is authorized, False otherwise.
    """
    try:
        cursor = connection.cursor()
        cursor.execute("SELECT hashed_password FROM authorized_users WHERE user_id = ?", (userId,))
        result = cursor.fetchone()

        if result:
            # Verify the password
            hashed_password = result[0]
            # In a real application, you'd likely have a login form and compare the entered password
            # with the hashed password stored in the database.  For this example, we'll assume
            # the user is authorized if the user ID exists.  A proper login mechanism is needed.
            logging.info(f"User {userId} authorized.")
            return True
        else:
            logging.warning(f"User {userId} not authorized.")
            return False
    except sqlite3.Error as e:
        logging.error(f"Error checking authorization for user {userId}: {e}")
        return False


def getUserBankAccount(userId: str, connection: sqlite3.Connection) -> Optional[dict]:
    """
    Retrieves bank account information for a user, but only if the user is authorized.

    Args:
        userId: The ID of the user whose account information to retrieve.
        connection: An open database connection.

    Returns:
        A dictionary containing the user's bank account information, or None if
        the user is not authorized or an error occurs.  The dictionary keys
        should correspond to the column names in the database table.

    Raises:
        Exception: If there is an error retrieving the account information from the database.
    """

    # Input Validation Examples:
    if not isinstance(userId, str):
        logging.warning(f"Invalid user ID type: {type(userId)}")
        return None

    if not re.match(r"^[a-zA-Z0-9_-]+$", userId):  # Example: Allow only alphanumeric characters, underscores, and hyphens
        logging.warning(f"Invalid user ID format: {userId}")
        return None

    if len(userId) > 50:  # Example: Limit the length of the user ID
        logging.warning(f"User ID too long: {userId}")
        return None

    if not isAuthorizedUser(userId, connection):
        logging.warning(f"Unauthorized access attempt for user ID: {userId}")
        return None

    try:
        cursor = connection.cursor()

        # Use parameterized query to prevent SQL injection
        query = "SELECT account_number, balance, account_type FROM bank_accounts WHERE user_id = ?"
        cursor.execute(query, (userId,))  # Pass userId as a tuple

        result = cursor.fetchone()

        if result:
            # Convert the result tuple to a dictionary for easier access
            account_info = {
                "account_number": result[0],
                "balance": result[1],
                "account_type": result[2]
            }
            logging.info(f"Successfully retrieved account information for user ID: {userId}")
            return account_info
        else:
            logging.warning(f"No account found for user ID: {userId}")
            return None

    except sqlite3.Error as e:
        logging.error(f"Error retrieving account information for user ID {userId}: {e}")
        raise Exception("Error retrieving account information.")  # Generic error message
    except Exception as e:
        logging.error(f"Unexpected error retrieving account information for user ID {userId}: {e}")
        raise Exception("Unexpected error retrieving account information.")


# Example usage (replace with your actual database connection)
def get_db_connection() -> sqlite3.Connection:
    """
    Establishes a connection to the SQLite database.  This function should be
    modified to use your actual database connection details.  It's crucial to
    handle connection errors gracefully.

    Returns:
        A database connection object.

    Raises:
        sqlite3.Error: If a connection to the database cannot be established.
    """
    try:
        conn = sqlite3.connect(DB_FILE)  # Replace with your database file
        conn.row_factory = sqlite3.Row  # Access columns by name
        return conn
    except sqlite3.Error as e:
        logging.error(f"Error connecting to the database: {e}")
        raise  # Re-raise the exception to signal the failure

def create_user_table(connection: sqlite3.Connection):
    """Creates the bank_accounts table if it doesn't exist."""
    try:
        cursor = connection.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS bank_accounts (
                user_id TEXT NOT NULL,
                account_number TEXT NOT NULL PRIMARY KEY,
                balance REAL NOT NULL,
                account_type TEXT NOT NULL
            )
        """)
        connection.commit()
        logging.info("Bank accounts table created (if it didn't exist).")
    except sqlite3.Error as e:
        logging.error(f"Error creating bank accounts table: {e}")
        raise

def create_authorized_users_table(connection: sqlite3.Connection):
    """Creates the authorized_users table if it doesn't exist."""
    try:
        cursor = connection.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS authorized_users (
                user_id TEXT NOT NULL PRIMARY KEY,
                hashed_password TEXT NOT NULL,
                role TEXT DEFAULT 'user'  -- Example: Role-Based Access Control
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_user_id ON authorized_users (user_id)") # Index for performance
        connection.commit()
        logging.info("Authorized users table created (if it didn't exist).")
    except sqlite3.Error as e:
        logging.error(f"Error creating authorized users table: {e}")
        raise

def create_default_user(connection: sqlite3.Connection):
    """Creates a default user if the authorized_users table is empty."""
    try:
        cursor = connection.cursor()
        cursor.execute("SELECT COUNT(*) FROM authorized_users")
        count = cursor.fetchone()[0]
        if count == 0:
            # Generate a random password
            alphabet = string.ascii_letters + string.digits + string.punctuation
            password = ''.join(secrets.choice(alphabet) for i in range(16))  # Generate a 16-character random password

            # Hash the password
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

            cursor.execute("INSERT INTO authorized_users (user_id, hashed_password) VALUES (?, ?)", (DB_USER, hashed_password.decode('utf-8')))
            connection.commit()
            logging.warning(f"Default user created with a randomly generated password.  This is for development/testing ONLY.  Password: {password}") # Log the password for testing purposes ONLY.  REMOVE IN PRODUCTION.
        else:
            logging.info("Authorized users table is not empty, skipping default user creation.")
    except sqlite3.Error as e:
        logging.error(f"Error creating default user: {e}")
        raise

def main():
    """
    Main function to demonstrate the usage of the getUserBankAccount function.
    """
    try:
        with get_db_connection() as conn:
            create_user_table(conn) # Ensure the bank_accounts table exists
            create_authorized_users_table(conn) # Ensure the authorized_users table exists
            create_default_user(conn) # Create a default user if the table is empty

            # Example user ID
            user_id = DB_USER # Use the default user

            # Get the user's bank account information
            account_info = getUserBankAccount(user_id, conn)

            if account_info:
                print(f"Account Information for User {user_id}:")
                print(f"Account Number: {account_info['account_number']}")
                print(f"Balance: {account_info['balance']}")
                print(f"Account Type: {account_info['account_type']}")
            else:
                print(f"Could not retrieve account information for user {user_id}.")

    except Exception as e:
        print(f"An error occurred: {e}")


if __name__ == "__main__":
    main()

