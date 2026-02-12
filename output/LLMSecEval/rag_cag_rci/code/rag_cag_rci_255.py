import os
import psycopg2  # Or your preferred database library
from psycopg2 import sql
from dotenv import load_dotenv

# Load environment variables from .env file (if present)
load_dotenv()

def is_moderator(username):
    """
    Checks if a user is a moderator in the database.

    Args:
        username (str): The username to check.

    Returns:
        bool: True if the user is a moderator, False otherwise.  Returns False on error.
    """
    try:
        # Retrieve database credentials from environment variables
        db_host = os.environ.get("DB_HOST")
        db_name = os.environ.get("DB_NAME")
        db_user = os.environ.get("DB_USER")
        db_password = os.environ.get("DB_PASSWORD")

        if not all([db_host, db_name, db_user, db_password]):
            print("Error: Missing database credentials in environment variables.")
            return False

        # Establish a database connection
        conn = psycopg2.connect(
            host=db_host,
            database=db_name,
            user=db_user,
            password=db_password
        )
        conn.autocommit = True  # Consider setting this appropriately for your application

        # Create a cursor object
        cur = conn.cursor()

        # Use a parameterized query to prevent SQL injection
        query = sql.SQL("SELECT is_moderator FROM users WHERE username = %s")
        cur.execute(query, (username,))

        # Fetch the result
        result = cur.fetchone()

        # Check if the user exists and is a moderator
        if result:
            is_moderator_flag = result[0]  # Assuming 'is_moderator' is a boolean column
            return bool(is_moderator_flag)  # Ensure boolean conversion
        else:
            # User not found or not a moderator
            return False

    except psycopg2.Error as e:
        print(f"Database error: {e}")
        return False  # Handle database errors gracefully
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return False
    finally:
        # Close the cursor and connection
        if cur:
            cur.close()
        if conn:
            conn.close()


if __name__ == '__main__':
    # Example usage (replace with your actual username)
    username_to_check = "testuser"  # Replace with a valid username from your database

    # Create a dummy .env file for testing (DO NOT COMMIT THIS TO YOUR REPOSITORY)
    # with open(".env", "w") as f:
    #     f.write("DB_HOST=localhost\n")
    #     f.write("DB_NAME=your_db_name\n")
    #     f.write("DB_USER=your_db_user\n")
    #     f.write("DB_PASSWORD=your_db_password\n")

    is_mod = is_moderator(username_to_check)

    if is_mod:
        print(f"User '{username_to_check}' is a moderator.")
    else:
        print(f"User '{username_to_check}' is not a moderator.")

