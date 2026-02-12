import os
import psycopg2
from psycopg2 import sql
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

def is_moderator(username):
    """
    Checks if a user is a moderator in the database.

    Args:
        username (str): The username to check.

    Returns:
        bool: True if the user is a moderator, False otherwise.
    """

    try:
        # Retrieve database credentials from environment variables
        db_host = os.environ.get("DB_HOST")
        db_name = os.environ.get("DB_NAME")
        db_user = os.environ.get("DB_USER")
        db_password = os.environ.get("DB_PASSWORD")
        db_port = os.environ.get("DB_PORT", 5432)  # Default port is 5432

        # Input validation: Check if username is a string and not empty
        if not isinstance(username, str) or not username:
            raise ValueError("Invalid username. Username must be a non-empty string.")

        # Establish a connection to the database
        conn = psycopg2.connect(
            host=db_host,
            database=db_name,
            user=db_user,
            password=db_password,
            port=db_port
        )

        # Create a cursor object
        cur = conn.cursor()

        # Use a parameterized query to prevent SQL injection
        query = sql.SQL("SELECT is_moderator FROM users WHERE username = %s").format()
        cur.execute(query, (username,))

        # Fetch the result
        result = cur.fetchone()

        # Check if the user exists and is a moderator
        if result:
            is_moderator_flag = result[0]
            return bool(is_moderator_flag)  # Convert to boolean
        else:
            return False  # User not found or not a moderator

    except psycopg2.Error as e:
        print(f"Database error: {e}")
        return False  # Handle database errors gracefully
    except ValueError as e:
        print(f"Input error: {e}")
        return False # Handle input validation errors
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return False # Handle unexpected errors

    finally:
        # Close the cursor and connection
        if cur:
            cur.close()
        if conn:
            conn.close()

if __name__ == '__main__':
    # Example usage:
    username_to_check = "testuser"  # Replace with the actual username
    is_mod = is_moderator(username_to_check)

    if is_mod:
        print(f"User '{username_to_check}' is a moderator.")
    else:
        print(f"User '{username_to_check}' is not a moderator.")

