import os
import psycopg2
from psycopg2 import sql
from dotenv import load_dotenv
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def is_moderator(username):
    """
    Checks if a user is a moderator in the database.

    Args:
        username (str): The username to check.

    Returns:
        bool: True if the user is a moderator, False otherwise.  Returns False on error.
    """

    # Input validation:  Check username length and allowed characters.  This is crucial.
    if not isinstance(username, str):
        logging.warning("Username must be a string.")
        return False

    if not (1 <= len(username) <= 50):  # Example length constraint
        logging.warning(f"Username '{username}' length is invalid. Must be between 1 and 50 characters.")
        return False

    if not username.isalnum(): # Example: Only allow alphanumeric characters
        logging.warning(f"Username '{username}' contains invalid characters. Must be alphanumeric.")
        return False


    db_host = os.environ.get("DB_HOST")
    db_name = os.environ.get("DB_NAME")
    db_user = os.environ.get("DB_USER")
    db_password = os.environ.get("DB_PASSWORD")
    db_port = os.environ.get("DB_PORT", "5432")  # Default port if not in env

    if not all([db_host, db_name, db_user, db_password]):
        logging.error("Database credentials not found in environment variables.")
        return False

    conn = None  # Initialize conn to None
    cur = None   # Initialize cur to None

    try:
        # Establish database connection
        conn = psycopg2.connect(
            host=db_host,
            database=db_name,
            user=db_user,
            password=db_password,
            port=db_port,
            sslmode='require'  # Add SSL/TLS for secure connection
        )
        conn.autocommit = True  # Consider using a transaction context manager for more complex operations

        # Create a cursor object
        cur = conn.cursor()

        # Use a parameterized query to prevent SQL injection
        query = sql.SQL("SELECT is_moderator FROM users WHERE username = %s")
        cur.execute(query, (username,))

        # Fetch the result
        result = cur.fetchone()

        if result:
            is_mod = result[0]
            logging.info(f"User '{username}' is {'a' if is_mod else 'not a'} moderator.")
            return is_mod  # Assuming the 'is_moderator' column is a boolean
        else:
            logging.info("User not found or not a moderator.") # More generic message
            return False  # User not found or not a moderator

    except psycopg2.Error as e:
        logging.error(f"Database error: {e.pgcode} - {e.pgerror}")  # Log specific error code and message
        return False  # Handle database errors gracefully
    finally:
        # Close the cursor and connection
        if cur:
            try:
                cur.close()
            except Exception as e:
                logging.error(f"Error closing cursor: {e}")
        if conn:
            try:
                conn.close()
            except Exception as e:
                logging.error(f"Error closing connection: {e}")

# Example usage remains the same

