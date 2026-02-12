import psycopg2
import os
import re
from dotenv import load_dotenv
import logging
import time  # Import time for potential timing attack mitigation
import unicodedata # Import for normalization

# Configure logging
logging.basicConfig(level=logging.ERROR, format='%(asctime)s - %(levelname)s - %(message)s')

# Load environment variables from .env file (if it exists)
load_dotenv()

def check_username_exists(username):
    """
    Checks if a username exists in the database.

    Args:
        username (str): The username to check.

    Returns:
        bool: True if the username exists, False otherwise.  Returns None if there's a connection error or invalid input.
    """

    # Input validation: Check username length and allowed characters
    if not (3 <= len(username) <= 50 and re.match("^[a-zA-Z0-9_]+$", username)):
        logging.error(f"Invalid username format: {username}")
        return None  # Indicate invalid input

    # Normalize username to lowercase
    username = username.lower()

    # (Optional) Implement more advanced canonicalization if needed
    # For example, using unicodedata.normalize('NFKC', username)
    # username = unicodedata.normalize('NFKC', username)

    try:
        # Retrieve database credentials from environment variables
        db_host = os.environ.get("DB_HOST")
        db_name = os.environ.get("DB_NAME")
        db_user = os.environ.get("DB_USER")
        db_password = os.environ.get("DB_PASSWORD")
        db_port = os.environ.get("DB_PORT", "5432")  # Default port if not specified

        # Ensure all required environment variables are set
        if not all([db_host, db_name, db_user, db_password]):
            logging.error("Missing database credentials in environment variables.")
            return None  # Indicate a configuration error

        # Convert db_port to integer
        try:
            db_port = int(db_port)
        except ValueError:
            logging.error(f"Invalid database port: {db_port}")
            return None

        # Establish a connection to the database
        try:
            conn = psycopg2.connect(
                host=db_host,
                database=db_name,
                user=db_user,
                password=db_password,
                port=db_port
            )
        except psycopg2.OperationalError as e:
            logging.error(f"Failed to connect to the database: {e}")
            return None


        # Create a cursor object to execute SQL queries
        try:
            cur = conn.cursor()
        except psycopg2.Error as e:
            logging.error(f"Failed to create cursor: {e}")
            return None


        # SQL query to check if the username exists (using parameterized query)
        query = "SELECT EXISTS (SELECT 1 FROM users WHERE username = %s);"

        # Execute the query with the username as a parameter (prevents SQL injection)
        try:
            cur.execute(query, (username,))
            # Add a small delay to mitigate timing attacks (optional, but consider)
            # time.sleep(0.01) # Requires import time
        except psycopg2.Error as e:
            logging.error(f"Failed to execute query: {e}")
            return None


        # Fetch the result
        try:
            exists = cur.fetchone()[0]  # Returns True or False
        except psycopg2.Error as e:
            logging.error(f"Failed to fetch result: {e}")
            return None

        # NOTE: Consider implementing rate limiting at the application level
        # to prevent DoS attacks if this function is exposed to the internet.
        return exists

    except Exception as e:
        logging.exception("An unexpected error occurred:")  # Log the full traceback
        return None  # Indicate a general error

    finally:
        # Ensure the cursor and connection are closed, even if an exception occurred
        if 'cur' in locals() and cur:
            try:
                cur.close()
            except psycopg2.Error as e:
                logging.error(f"Error closing cursor: {e}")
        if 'conn' in locals() and conn:
            try:
                conn.close()
            except psycopg2.Error as e:
                logging.error(f"Error closing connection: {e}")


if __name__ == '__main__':
    # Example usage:
    username_to_check = "testuser"  # Replace with the username you want to check

    exists = check_username_exists(username_to_check)

    if exists is True:
        print(f"Username '{username_to_check}' exists in the database.")
    elif exists is False:
        print(f"Username '{username_to_check}' does not exist in the database.")
    else:
        print("An error occurred while checking the username. Check the database connection and credentials, and username format.")

