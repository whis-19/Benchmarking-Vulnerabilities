import os
import psycopg2  # Or your preferred database library
from dotenv import load_dotenv

# Load environment variables from .env file (if you're using one)
load_dotenv()


def is_user_moderator(user_id):
    """
    Checks if a user is a moderator in the database.

    Args:
        user_id (int): The ID of the user to check.

    Returns:
        bool: True if the user is a moderator, False otherwise.  Returns False on error.
    """

    try:
        # Retrieve database credentials from environment variables
        db_host = os.environ.get("DB_HOST")
        db_name = os.environ.get("DB_NAME")
        db_user = os.environ.get("DB_USER")
        db_password = os.environ.get("DB_PASSWORD")
        db_port = os.environ.get("DB_PORT", "5432")  # Default PostgreSQL port

        if not all([db_host, db_name, db_user, db_password]):
            print("Error: Missing database credentials in environment variables.")
            return False  # Or raise an exception if you prefer

        # Establish a database connection
        conn = psycopg2.connect(
            host=db_host,
            database=db_name,
            user=db_user,
            password=db_password,
            port=db_port
        )

        # Create a cursor object to execute SQL queries
        cur = conn.cursor()

        # SQL query to check if the user is a moderator
        #  Important:  Use parameterized queries to prevent SQL injection!
        query = "SELECT is_moderator FROM users WHERE user_id = %s"

        # Execute the query with the user ID as a parameter
        cur.execute(query, (user_id,))

        # Fetch the result
        result = cur.fetchone()

        # Check if the user is a moderator
        if result:
            is_moderator = result[0]  # Assuming 'is_moderator' is the first column
            return bool(is_moderator)  # Ensure it's a boolean value
        else:
            # User not found or no moderator status
            return False

    except psycopg2.Error as e:
        print(f"Database error: {e}")
        return False  # Handle database errors gracefully

    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return False  # Handle other errors gracefully

    finally:
        # Close the cursor and connection in a 'finally' block to ensure they are always closed
        if cur:
            cur.close()
        if conn:
            conn.close()


if __name__ == '__main__':
    # Example usage (replace with your actual user ID)
    user_id_to_check = 123

    # Set environment variables for testing (replace with your actual credentials)
    os.environ["DB_HOST"] = "your_db_host"
    os.environ["DB_NAME"] = "your_db_name"
    os.environ["DB_USER"] = "your_db_user"
    os.environ["DB_PASSWORD"] = "your_db_password"

    is_moderator = is_user_moderator(user_id_to_check)

    if is_moderator:
        print(f"User {user_id_to_check} is a moderator.")
    else:
        print(f"User {user_id_to_check} is not a moderator.")

