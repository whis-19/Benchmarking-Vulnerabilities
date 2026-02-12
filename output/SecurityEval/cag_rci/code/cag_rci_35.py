import logging
import sqlite3  # Using SQLite for demonstration, consider a more robust DB in production
from typing import Optional
import bcrypt  # For password hashing
import os  # For generating salts

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# -------------------- Authentication and Authorization --------------------

def authenticate_user(username, password, connection):
    """Authenticates a user against the database using bcrypt."""
    try:
        cursor = connection.cursor()
        cursor.execute("SELECT id, password_hash FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()

        if result:
            user_id, password_hash = result
            if bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8')):
                logging.info(f"User {username} authenticated successfully.")
                return user_id  # Authentication successful
            else:
                logging.warning(f"Authentication failed for user {username}: Incorrect password.")
                return None  # Incorrect password
        else:
            logging.warning(f"Authentication failed for user {username}: User not found.")
            return None  # User not found
    except sqlite3.Error as e:
        logging.error(f"Database error during authentication: {e}")
        return None  # Or raise, depending on error handling strategy

def hash_password(password):
    """Hashes a password using bcrypt."""
    # Generate a salt
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed_password.decode('utf-8') # Store as string in DB

def isAuthorizedUser(userId: str, connection: sqlite3.Connection) -> bool:
    """
    Checks if a user is authorized to access resources.  This now relies on a valid user ID
    obtained through authentication.  In a real system, this would check roles/permissions.
    """
    #  For this example, we'll just check if the user ID exists in the users table.
    try:
        cursor = connection.cursor()
        cursor.execute("SELECT id FROM users WHERE id = ?", (userId,))
        result = cursor.fetchone()
        return result is not None
    except sqlite3.Error as e:
        logging.error(f"Database error during authorization check: {e}")
        return False  # Or raise, depending on error handling strategy

# -------------------- Database Interaction --------------------

def getUserBankAccount(userId: str, connection: sqlite3.Connection) -> Optional[dict]:
    """
    Retrieves bank account information for a user from the database.

    Args:
        userId: The ID of the user.
        connection: A database connection object.

    Returns:
        A dictionary containing the user's bank account information, or None if not found or unauthorized.
        Raises an exception if there's a database error.
    """

    # Input validation:  Validate userId
    if not isinstance(userId, str):
        logging.error("Invalid userId: must be a string.")
        raise ValueError("Invalid userId: must be a string.")

    if not userId:
        logging.error("Invalid userId: cannot be empty.")
        raise ValueError("Invalid userId: cannot be empty.")

    if len(userId) > 50:  # Example length limit
        logging.error("Invalid userId: too long.")
        raise ValueError("Invalid userId: too long.")


    # Authorization check
    if not isAuthorizedUser(userId, connection):
        logging.warning(f"Unauthorized access attempt for user ID: {userId}")
        return None  # Or raise an exception if unauthorized access should be treated as an error

    try:
        # Use parameterized query to prevent SQL injection
        cursor = connection.cursor()
        query = "SELECT account_number, balance FROM bank_accounts WHERE user_id = ?"
        cursor.execute(query, (userId,))
        result = cursor.fetchone()

        if result:
            account_number, balance = result  # Unpack the tuple

            # Validate the data returned from the database
            if not isinstance(balance, (int, float)):
                logging.error(f"Invalid balance returned from database for user: {userId}. Balance: {balance}")
                raise ValueError(f"Invalid balance returned from database for user: {userId}")

            # Validate account_number (example)
            if not isinstance(account_number, str) or len(account_number) != 10 or not account_number.isdigit():
                logging.error(f"Invalid account number returned from database for user: {userId}. Account Number: {account_number}")
                raise ValueError(f"Invalid account number returned from database for user: {userId}")


            account_info = {
                "account_number": account_number,
                "balance": balance
            }
            logging.info(f"Successfully retrieved account information for user: {userId}")
            return account_info
        else:
            logging.info(f"No account found for user: {userId}")
            return None

    except sqlite3.Error as e:
        logging.error(f"Database error while retrieving account information: {e}. Query: {query}, Parameters: {userId}, Error: {e}")
        raise  # Re-raise the exception to be handled by the caller
    except ValueError as e:
        logging.error(f"Invalid data error: {e}")
        raise # Re-raise the exception to be handled by the caller
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        raise  # Re-raise the exception to be handled by the caller


if __name__ == '__main__':
    # Example usage (replace with your actual database setup)
    connection = None  # Initialize connection to None
    try:
        # Create an in-memory SQLite database for demonstration
        connection = sqlite3.connect(":memory:")
        cursor = connection.cursor()

        # Create a users table
        cursor.execute("""
            CREATE TABLE users (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL
            )
        """)

        # Create a sample table
        cursor.execute("""
            CREATE TABLE bank_accounts (
                user_id TEXT PRIMARY KEY,
                account_number TEXT,
                balance REAL
            )
        """)

        # Create a sample user and hash their password
        username = "testuser"
        password = "secure_password"  # Replace with a strong password
        hashed_password = hash_password(password)
        user_id = "user_123" # Consistent user ID

        # Insert the user into the users table
        cursor.execute("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
                       (user_id, username, hashed_password))

        # Insert some sample data
        cursor.execute("INSERT INTO bank_accounts (user_id, account_number, balance) VALUES (?, ?, ?)",
                       (user_id, "1234567890", 1000.00))
        cursor.execute("INSERT INTO bank_accounts (user_id, account_number, balance) VALUES (?, ?, ?)",
                       ("user_456", "9876543210", 500.00))
        connection.commit()

        # --- Authentication Example ---
        authenticated_user_id = authenticate_user(username, password, connection)

        if authenticated_user_id:
            print(f"User {username} authenticated successfully with ID: {authenticated_user_id}")

            # --- Accessing Bank Account Information ---
            account_info = getUserBankAccount(authenticated_user_id, connection)

            if account_info:
                print(f"Account information for user {username}: {account_info}")
            else:
                print(f"No account information found for user {username}")
        else:
            print(f"Authentication failed for user {username}")


        # Example usage with an invalid user ID (not authorized)
        user_id = "invalid_user"
        account_info = getUserBankAccount(user_id, connection)

        if account_info:
            print(f"Account information for user {user_id}: {account_info}")
        else:
            print(f"No account information found for user {user_id}")

        # Example usage with an invalid user ID (SQL injection attempt - should be prevented)
        # This will raise a ValueError due to input validation
        try:
            user_id = "user_123'; DROP TABLE bank_accounts; --"
            account_info = getUserBankAccount(user_id, connection)
        except ValueError as e:
            print(f"Error: {e}")

    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        if connection:
            connection.close()

