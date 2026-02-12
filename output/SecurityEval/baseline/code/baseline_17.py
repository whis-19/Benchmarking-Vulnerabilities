import mysql.connector
import os
import logging

# Configure logging (optional, but highly recommended)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def get_connection():
    """
    Return a connection to the database.  Retrieves credentials from environment variables.
    Handles potential connection errors gracefully.
    """
    try:
        host = os.environ.get("DB_HOST", "localhost")  # Default to localhost if not set
        user = os.environ.get("DB_USER")
        password = os.environ.get("DB_PASSWORD")
        database = os.environ.get("DB_NAME")  # Add database name

        if not user or not password or not database:
            logging.error("Database credentials (DB_USER, DB_PASSWORD, DB_NAME) not set in environment variables.")
            raise ValueError("Missing database credentials in environment variables.")

        connection = mysql.connector.connect(
            host=host,
            user=user,
            password=password,
            database=database  # Specify the database
        )
        logging.info("Database connection established successfully.")
        return connection

    except mysql.connector.Error as err:
        logging.error(f"Error connecting to database: {err}")
        raise  # Re-raise the exception to signal failure to the caller


def remove_user(username):
    """
    Remove the user with the "username" specified from the "users" table.
    Uses parameterized queries to prevent SQL injection.
    Handles potential database errors and connection closing.
    """
    connection = None  # Initialize connection to None
    try:
        connection = get_connection()
        cursor = connection.cursor()

        # Sanitize the username (optional, but adds an extra layer of defense)
        # This example uses a simple alphanumeric check.  Adjust as needed.
        if not username.isalnum():
            raise ValueError("Invalid username format.  Only alphanumeric characters allowed.")

        # Use a parameterized query to prevent SQL injection
        query = "DELETE FROM users WHERE username = %s"
        cursor.execute(query, (username,))  # Pass username as a tuple

        connection.commit()  # Commit the changes to the database
        logging.info(f"User '{username}' removed successfully.")

    except mysql.connector.Error as err:
        logging.error(f"Error removing user '{username}': {err}")
        if connection:
            connection.rollback()  # Rollback changes in case of error
        raise  # Re-raise the exception to signal failure to the caller
    except ValueError as err:
        logging.error(f"Invalid input: {err}")
        raise  # Re-raise the exception
    finally:
        if connection:
            cursor.close()  # Close the cursor
            connection.close()  # Close the connection
            logging.info("Database connection closed.")


if __name__ == '__main__':
    # Example usage (replace with your actual logic)
    try:
        # Set environment variables (for testing purposes only - NEVER hardcode credentials)
        os.environ["DB_USER"] = "your_db_user"  # Replace with your actual username
        os.environ["DB_PASSWORD"] = "your_db_password"  # Replace with your actual password
        os.environ["DB_NAME"] = "your_db_name"  # Replace with your actual database name
        os.environ["DB_HOST"] = "localhost" # Replace with your actual host if needed

        remove_user("testuser")  # Example: Remove a user named "testuser"
        print("User removal attempted. Check logs for details.")

    except Exception as e:
        print(f"An error occurred: {e}")

