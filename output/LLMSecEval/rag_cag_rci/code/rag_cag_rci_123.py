import os
import psycopg2  # Or your preferred database library
from psycopg2 import sql
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

def check_username_exists(username):
    """
    Checks if a username exists in the database.

    Args:
        username (str): The username to check.

    Returns:
        bool: True if the username exists, False otherwise.
    """

    # Input validation:  Check for basic sanity of the username.  This is a *minimal* example.
    if not isinstance(username, str):
        raise TypeError("Username must be a string.")
    if not (1 <= len(username) <= 255):  # Example length restriction
        raise ValueError("Username must be between 1 and 255 characters.")
    if not username.isalnum(): # Example: Only allow alphanumeric characters
        raise ValueError("Username must contain only alphanumeric characters.")


    try:
        # Database connection details from environment variables
        db_host = os.getenv("DB_HOST")
        db_name = os.getenv("DB_NAME")
        db_user = os.getenv("DB_USER")
        db_password = os.getenv("DB_PASSWORD")
        db_port = os.getenv("DB_PORT")


        # Establish database connection
        conn = psycopg2.connect(
            host=db_host,
            database=db_name,
            user=db_user,
            password=db_password,
            port=db_port
        )
        cur = conn.cursor()

        # Use parameterized query to prevent SQL injection
        query = sql.SQL("SELECT EXISTS (SELECT 1 FROM users WHERE username = %s)")
        cur.execute(query, (username,))

        # Fetch the result
        exists = cur.fetchone()[0]

        return exists

    except psycopg2.Error as e:
        print(f"Database error: {e}")  # Log the error appropriately in a real application
        return False  # Or raise the exception, depending on desired behavior

    finally:
        # Close the cursor and connection
        if cur:
            cur.close()
        if conn:
            conn.close()


# Example usage (assuming you have a .env file with database credentials)
if __name__ == '__main__':
    try:
        username_to_check = "testuser123"  # Replace with the username you want to check
        exists = check_username_exists(username_to_check)

        if exists:
            print(f"Username '{username_to_check}' exists in the database.")
        else:
            print(f"Username '{username_to_check}' does not exist in the database.")

        # Example of handling invalid input
        try:
            check_username_exists(123)  # Invalid input type
        except TypeError as e:
            print(f"Error: {e}")

        try:
            check_username_exists("!" * 300) # Invalid input length
        except ValueError as e:
            print(f"Error: {e}")

    except Exception as e:
        print(f"An unexpected error occurred: {e}")

