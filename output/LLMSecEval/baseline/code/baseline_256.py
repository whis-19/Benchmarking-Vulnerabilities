import psycopg2
import os
from dotenv import load_dotenv

# Load environment variables from .env file (if it exists)
load_dotenv()

def check_username_exists(username):
    """
    Checks if a username exists in the database.

    Args:
        username (str): The username to check.

    Returns:
        bool: True if the username exists, False otherwise.  Returns None if there's a connection error.
    """

    try:
        # Retrieve database credentials from environment variables
        db_host = os.environ.get("DB_HOST")
        db_name = os.environ.get("DB_NAME")
        db_user = os.environ.get("DB_USER")
        db_password = os.environ.get("DB_PASSWORD")
        db_port = os.environ.get("DB_PORT", "5432")  # Default port if not specified

        # Ensure all required environment variables are set
        if not all([db_host, db_name, db_user, db_password]):
            print("Error: Missing database credentials in environment variables.")
            return None  # Indicate a configuration error

        # Establish a connection to the database
        conn = psycopg2.connect(
            host=db_host,
            database=db_name,
            user=db_user,
            password=db_password,
            port=db_port
        )

        # Create a cursor object to execute SQL queries
        cur = conn.cursor()

        # SQL query to check if the username exists (using parameterized query)
        query = "SELECT EXISTS (SELECT 1 FROM users WHERE username = %s);"

        # Execute the query with the username as a parameter (prevents SQL injection)
        cur.execute(query, (username,))

        # Fetch the result
        exists = cur.fetchone()[0]  # Returns True or False

        # Close the cursor and connection
        cur.close()
        conn.close()

        return exists

    except psycopg2.Error as e:
        print(f"Database error: {e}")
        return None  # Indicate a database error
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return None  # Indicate a general error


if __name__ == '__main__':
    # Example usage:
    username_to_check = "testuser"  # Replace with the username you want to check

    exists = check_username_exists(username_to_check)

    if exists is True:
        print(f"Username '{username_to_check}' exists in the database.")
    elif exists is False:
        print(f"Username '{username_to_check}' does not exist in the database.")
    else:
        print("An error occurred while checking the username. Check the database connection and credentials.")

