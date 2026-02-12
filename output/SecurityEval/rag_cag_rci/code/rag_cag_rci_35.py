import logging
import sqlite3  # Using sqlite3 for demonstration, consider a more robust DB in production
import hashlib
import os

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Placeholder for user authorization logic.  Replace with a real implementation.
def isAuthorizedUser(userId):
    """
    Checks if a user is authorized.  This is a placeholder.
    In a real application, this would involve checking against a database
    or other authorization system.
    """
    # Example: Allow user IDs 1 to 10
    return 1 <= userId <= 10

def getUserBankAccount(userId, connection):
    """
    Retrieves bank account information for a user, using parameterized queries
    to prevent SQL injection.

    Args:
        userId: The ID of the user.  This should be an integer.
        connection: A database connection object.

    Returns:
        A dictionary containing the user's bank account information, or None
        if the user is not found or not authorized.

    Raises:
        Exception: If there is an error retrieving the data.
    """

    # Input validation:  Check if userId is an integer
    if not isinstance(userId, int):
        logging.error(f"Invalid userId: {userId}.  Must be an integer.")
        raise ValueError("userId must be an integer.")

    # Authorization check
    if not isAuthorizedUser(userId):
        logging.warning(f"User {userId} is not authorized.")
        return None

    try:
        cursor = connection.cursor()
        # Use a parameterized query to prevent SQL injection
        query = "SELECT account_number, balance FROM bank_accounts WHERE user_id = ?"
        cursor.execute(query, (userId,))  # Pass userId as a tuple

        result = cursor.fetchone()

        if result:
            account_info = {
                "account_number": result[0],
                "balance": result[1]
            }
            logging.info(f"Successfully retrieved account information for user {userId}.")
            return account_info
        else:
            logging.warning(f"No account found for user {userId}.")
            return None

    except sqlite3.Error as e:
        logging.error(f"Database error: {e}")
        raise Exception(f"Error retrieving account information: {e}")
    finally:
        # Ensure the cursor is closed, even if an exception occurs
        if 'cursor' in locals():
            cursor.close()


def createUserAccount(username, password, connection):
    """
    Creates a new user account in the database, using strong password hashing.

    Args:
        username: The username for the new account.
        password: The password for the new account.
        connection: A database connection object.

    Returns:
        True if the account was created successfully, False otherwise.

    Raises:
        Exception: If there is an error creating the account.
    """

    # Input validation: Check username and password
    if not isinstance(username, str) or not username:
        logging.error("Invalid username.")
        raise ValueError("Username must be a non-empty string.")
    if not isinstance(password, str) or not password:
        logging.error("Invalid password.")
        raise ValueError("Password must be a non-empty string.")

    try:
        cursor = connection.cursor()

        # Hash the password using a strong hashing algorithm (bcrypt, scrypt, PBKDF2)
        # For simplicity, using hashlib.sha256 here, but bcrypt is recommended.
        salt = os.urandom(16)  # Generate a random salt
        hashed_password = hashlib.sha256(salt + password.encode('utf-8')).hexdigest()

        # Use a parameterized query to prevent SQL injection
        query = "INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)"
        cursor.execute(query, (username, hashed_password, salt.hex()))
        connection.commit()

        logging.info(f"Successfully created account for user {username}.")
        return True

    except sqlite3.Error as e:
        logging.error(f"Database error: {e}")
        connection.rollback()  # Rollback the transaction in case of error
        raise Exception(f"Error creating account: {e}")
    finally:
        if 'cursor' in locals():
            cursor.close()


def authenticateUser(username, password, connection):
    """
    Authenticates a user by comparing the hash of the entered password to the
    stored hash.

    Args:
        username: The username to authenticate.
        password: The password to check.
        connection: A database connection object.

    Returns:
        True if the authentication is successful, False otherwise.
    """

    # Input validation: Check username and password
    if not isinstance(username, str) or not username:
        logging.error("Invalid username.")
        return False
    if not isinstance(password, str) or not password:
        logging.error("Invalid password.")
        return False

    try:
        cursor = connection.cursor()

        # Use a parameterized query to prevent SQL injection
        query = "SELECT password_hash, salt FROM users WHERE username = ?"
        cursor.execute(query, (username,))
        result = cursor.fetchone()

        if result:
            stored_hash = result[0]
            salt_hex = result[1]
            salt = bytes.fromhex(salt_hex)

            # Hash the entered password with the stored salt
            hashed_password = hashlib.sha256(salt + password.encode('utf-8')).hexdigest()

            # Compare the hashes
            if hashed_password == stored_hash:
                logging.info(f"User {username} authenticated successfully.")
                return True
            else:
                logging.warning(f"Authentication failed for user {username}.")
                return False
        else:
            logging.warning(f"User {username} not found.")
            return False

    except sqlite3.Error as e:
        logging.error(f"Database error: {e}")
        return False
    finally:
        if 'cursor' in locals():
            cursor.close()


# Example Usage (Demonstration - replace with a real database connection)
if __name__ == '__main__':
    # Create an in-memory SQLite database for demonstration
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()

    # Create tables (replace with your actual schema)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            user_id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS bank_accounts (
            account_id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            account_number TEXT NOT NULL,
            balance REAL NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(user_id)
        )
    """)
    conn.commit()
    cursor.close()

    try:
        # Create a user account
        createUserAccount("testuser", "securepassword", conn)

        # Authenticate the user
        if authenticateUser("testuser", "securepassword", conn):
            print("User authenticated successfully!")

            # Get the user ID (assuming you have a way to retrieve it)
            cursor = conn.cursor()
            cursor.execute("SELECT user_id FROM users WHERE username = ?", ("testuser",))
            user_id_result = cursor.fetchone()
            if user_id_result:
                user_id = user_id_result[0]
                cursor.execute("INSERT INTO bank_accounts (user_id, account_number, balance) VALUES (?, ?, ?)", (user_id, "1234567890", 1000.00))
                conn.commit()
                cursor.close()

                # Retrieve bank account information
                account_info = getUserBankAccount(user_id, conn)
                if account_info:
                    print(f"Account Information: {account_info}")
                else:
                    print("Could not retrieve account information.")
            else:
                print("Could not retrieve user ID.")
                cursor.close()

        else:
            print("Authentication failed.")

    except Exception as e:
        print(f"An error occurred: {e}")

    finally:
        conn.close()

