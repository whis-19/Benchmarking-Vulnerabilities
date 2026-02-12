import os
import psycopg2  # Or your preferred database library
from dotenv import load_dotenv
import logging
from typing import Optional

# Configure logging (optional, but highly recommended for production)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Load environment variables from .env file (if you're using one)
load_dotenv()

def is_user_moderator(user_id: int) -> bool:
    """
    Checks if a user is a moderator in the database.

    Args:
        user_id (int): The ID of the user to check.

    Returns:
        bool: True if the user is a moderator, False otherwise.  Returns False if any error occurs.
    """
    conn: Optional[psycopg2.extensions.connection] = None  # Initialize conn to None
    cur: Optional[psycopg2.extensions.cursor] = None   # Initialize cur to None
    try:
        # Retrieve database credentials from environment variables
        env_vars = {
            "DB_HOST": os.environ.get("DB_HOST"),
            "DB_NAME": os.environ.get("DB_NAME"),
            "DB_USER": os.environ.get("DB_USER"),
            "DB_PASSWORD": os.environ.get("DB_PASSWORD"),
            "DB_PORT": os.environ.get("DB_PORT", "5432")  # Default PostgreSQL port
        }

        missing_vars = [key for key, value in env_vars.items() if not value]

        if missing_vars:
            for var in missing_vars:
                logging.error(f"Error: {var} environment variable is missing.")
            return False

        db_host = env_vars["DB_HOST"]
        db_name = env_vars["DB_NAME"]
        db_user = env_vars["DB_USER"]
        db_password = env_vars["DB_PASSWORD"]
        db_port = env_vars["DB_PORT"]

        # Input Validation: Ensure user_id is an integer
        if not isinstance(user_id, int):
            error_message = f"Error: user_id must be an integer. Received: {type(user_id)}"
            logging.error(error_message)
            return False

        # Establish a database connection
        conn = psycopg2.connect(
            host=db_host,
            database=db_name,
            user=db_user,
            password=db_password,
            port=db_port,
            connect_timeout=5  # Add a 5-second connection timeout
        )

        # Create a cursor object to execute SQL queries
        cur = conn.cursor()

        # SQL query to check if the user is a moderator
        query = "SELECT is_moderator FROM users WHERE user_id = %s;"  # Use parameterized query
        cur.execute(query, (user_id,))  # Pass user_id as a parameter

        # Fetch the result
        result = cur.fetchone()

        # Check if the user is a moderator
        if result:
            is_moderator = result[0]  # Assuming 'is_moderator' is the first column
            return bool(is_moderator)  # Ensure boolean return value
        else:
            # User not found or no moderator status
            return False

    except psycopg2.Error as e:
        logging.exception("Database error occurred:")  # Log the full exception traceback
        return False  # Handle database errors gracefully
    except Exception as e:
        logging.exception("An unexpected error occurred:")  # Log the full exception traceback
        return False # Handle other errors gracefully
    finally:
        # Close the cursor and connection in a 'finally' block to ensure they are always closed
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


if __name__ == '__main__':
    # Example usage (replace with your actual user ID)
    user_id_to_check = 123
    is_mod = is_user_moderator(user_id_to_check)

    if is_mod:
        print(f"User {user_id_to_check} is a moderator.")
    else:
        print(f"User {user_id_to_check} is not a moderator.")

    user_id_to_check = "abc"  # Test with invalid user_id
    is_mod = is_user_moderator(user_id_to_check)

    if is_mod:
        print(f"User {user_id_to_check} is a moderator.")
    else:
        print(f"User {user_id_to_check} is not a moderator.")

