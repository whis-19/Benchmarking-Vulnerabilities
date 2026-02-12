import logging
import sqlite3  # Consider using a more robust database library for production
import os  # For environment variables
import bcrypt  # For password hashing

# Configure logging (adjust level as needed)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Custom Exceptions
class AuthenticationError(Exception):
    """Custom exception for authentication failures."""
    pass

class AuthorizationError(Exception):
    """Custom exception for authorization failures."""
    pass

class DatabaseError(Exception):
    """Custom exception for database-related errors."""
    pass


def hash_password(password):
    """Hashes a password using bcrypt."""
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    return hashed_password.decode('utf-8')


def verify_password(password, hashed_password):
    """Verifies a password against a bcrypt hash."""
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))


def authenticate_user(username, password, connection):
    """Authenticates a user against the database."""
    try:
        cursor = connection.cursor()
        query = "SELECT user_id, password_hash FROM users WHERE username = ?"
        cursor.execute(query, (username,))
        result = cursor.fetchone()

        if result:
            user_id, password_hash = result
            if verify_password(password, password_hash):
                logging.info(f"User {username} authenticated successfully.")
                return user_id
            else:
                logging.warning(f"Authentication failed for user {username}: Incorrect password.")
                raise AuthenticationError("Incorrect password.")
        else:
            logging.warning(f"Authentication failed for user {username}: User not found.")
            raise AuthenticationError("User not found.")
    except sqlite3.Error as e:
        logging.error(f"Database error during authentication: {e}")
        raise DatabaseError(f"Database error during authentication: {e}")
    finally:
        if 'cursor' in locals():
            cursor.close()


def isAuthorizedUser(userId, connection):
    """
    Checks if a user is authorized to access bank account information.
    In a real application, this would involve more sophisticated role-based access control.
    """
    try:
        user_id_int = int(userId)
        cursor = connection.cursor()
        query = "SELECT role FROM users WHERE user_id = ?"
        cursor.execute(query, (user_id_int,))
        result = cursor.fetchone()

        if result:
            role = result[0]
            # Example: Only users with the 'account_access' role are authorized
            if role == 'account_access':
                return True
            else:
                logging.warning(f"User ID {user_id_int} is not authorized to access bank accounts.")
                return False
        else:
            logging.warning(f"User ID {user_id_int} not found during authorization check.")
            return False
    except ValueError:
        logging.error(f"Invalid userId format: {userId}")
        return False
    except sqlite3.Error as e:
        logging.error(f"Database error during authorization check: {e}")
        raise DatabaseError(f"Database error during authorization check: {e}")
    finally:
        if 'cursor' in locals():
            cursor.close()


def getUserBankAccount(userId, connection):
    """
    Retrieves bank account information for a user, after authentication and authorization.
    """

    if not isinstance(userId, (int, str)):
        raise TypeError("userId must be an integer or string.")

    try:
        user_id_int = int(userId)
    except ValueError:
        raise ValueError("Invalid userId format. Must be convertible to an integer.")

    if not isinstance(connection, sqlite3.Connection):
        raise TypeError("connection must be a sqlite3.Connection object.")

    if not isAuthorizedUser(user_id_int, connection):
        logging.warning(f"Unauthorized access attempt for user ID: {user_id_int}")
        raise AuthorizationError(f"Unauthorized access for user ID: {user_id_int}")

    try:
        cursor = connection.cursor()
        query = "SELECT account_number, balance FROM bank_accounts WHERE user_id = ?"
        cursor.execute(query, (user_id_int,))
        result = cursor.fetchone()

        if result:
            account_info = {
                "account_number": result[0],
                "balance": result[1]
            }
            logging.info(f"Successfully retrieved account information for user ID: {user_id_int}")
            # Mask the account number for logging
            masked_account_number = account_info['account_number'][:4] + '...' + account_info['account_number'][-4:]
            logging.debug(f"Account information for user {user_id_int}: Account Number: {masked_account_number}, Balance: {account_info['balance']}")
            return account_info
        else:
            logging.info(f"No account found for user ID: {user_id_int}")
            return None

    except sqlite3.Error as e:
        logging.error(f"Error retrieving account information for user ID: {user_id_int}: {e}")
        raise DatabaseError(f"Error retrieving account information: {e}")
    finally:
        if 'cursor' in locals():
            cursor.close()


if __name__ == '__main__':
    try:
        # Create an in-memory SQLite database for testing
        conn = sqlite3.connect(':memory:')
        cursor = conn.cursor()

        # Create tables (users and bank_accounts)
        cursor.execute("""
            CREATE TABLE users (
                user_id INTEGER PRIMARY KEY,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'user'  -- e.g., 'user', 'admin', 'account_access'
            )
        """)

        cursor.execute("""
            CREATE TABLE bank_accounts (
                user_id INTEGER PRIMARY KEY,
                account_number TEXT NOT NULL,
                balance REAL NOT NULL
            )
        """)

        # Create a user with a hashed password and the 'account_access' role
        username = "testuser"
        password = "secure_password"
        hashed_password = hash_password(password)
        cursor.execute("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)", (username, hashed_password, "account_access"))

        # Insert sample data
        cursor.execute("INSERT INTO bank_accounts (user_id, account_number, balance) VALUES (?, ?, ?)", (1, "1234567890", 1000.00))
        conn.commit()

        # Authenticate the user
        try:
            user_id = authenticate_user(username, password, conn)
            print(f"User authenticated with ID: {user_id}")

            # Get account information
            account_info = getUserBankAccount(user_id, conn)

            if account_info:
                print(f"Account information for user {user_id}: {account_info}")
            else:
                print(f"No account found for user {user_id}")

        except AuthenticationError as e:
            print(f"Authentication Error: {e}")
        except AuthorizationError as e:
            print(f"Authorization Error: {e}")
        except DatabaseError as e:
            print(f"Database Error: {e}")


    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        if 'conn' in locals():
            conn.close()

