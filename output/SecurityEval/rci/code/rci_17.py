import mysql.connector
import os
import logging
from urllib.parse import urlparse, unquote
import re

# Configure logging (optional, but highly recommended)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def get_connection():
    """
    Return a connection to the database.  Retrieves credentials from environment variables.
    Handles potential connection errors gracefully.  Uses urllib.parse for DATABASE_URL parsing.
    """
    try:
        # Use a single database connection string
        db_url = os.environ.get("DATABASE_URL")

        if not db_url:
            host = os.environ.get("DB_HOST", "localhost")  # Default to localhost if not set
            user = os.environ.get("DB_USER")
            password = os.environ.get("DB_PASSWORD")
            database = os.environ.get("DB_NAME")  # Add database name

            if not user or not password or not database:
                logging.error("Database credentials (DB_USER, DB_PASSWORD, DB_NAME) or DATABASE_URL not set in environment variables.")
                raise ValueError("Missing database credentials in environment variables.")

            connection = mysql.connector.connect(
                host=host,
                user=user,
                password=password,
                database=database
            )
        else:
            # Use urllib.parse for robust URL parsing
            try:
                parsed_url = urlparse(db_url)
                host = parsed_url.hostname
                port = parsed_url.port or 3306  # Default MySQL port
                user = unquote(parsed_url.username)  # Decode URL-encoded characters
                password = unquote(parsed_url.password)  # Decode URL-encoded characters
                database = parsed_url.path[1:].lstrip('/')  # Remove leading slash

                if not all([host, user, password, database]):
                    logging.error("Incomplete DATABASE_URL information.")
                    raise ValueError("Incomplete DATABASE_URL information.")

                connection = mysql.connector.connect(
                    host=host,
                    user=user,
                    password=password,
                    database=database,
                    port=port
                )
            except Exception as e:
                logging.error(f"Error parsing DATABASE_URL: {e}")
                raise ValueError("Invalid DATABASE_URL") from e


        logging.info("Database connection established successfully.")
        return connection

    except mysql.connector.Error as err:
        logging.error(f"Error connecting to database: {err}")
        raise  # Re-raise the exception to signal failure to the caller
    except ValueError as err:
        logging.error(f"Error: {err}")
        raise


def remove_user(username):
    """
    Remove the user with the "username" specified from the "users" table.
    Uses parameterized queries (also known as prepared statements) to prevent SQL injection.
    Handles potential database errors gracefully.
    """
    connection = None  # Initialize connection to None
    cursor = None  # Initialize cursor to None
    try:
        connection = get_connection()
        cursor = connection.cursor()

        # Sanitize the username (optional, but adds an extra layer of defense)
        # This example uses a regular expression.  Adjust as needed.
        if not re.match(r"^[a-zA-Z0-9_-]{3,16}$", username):
            logging.warning(f"Invalid username format: {username}.  Must be 3-16 alphanumeric characters, underscores, or hyphens. Operation aborted.")
            raise ValueError("Invalid username format.  Only alphanumeric characters, underscores, and hyphens allowed (3-16 characters).")


        # Use a parameterized query (also known as a prepared statement) to prevent SQL injection
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
        logging.error(f"Error: {err}")
        raise
    finally:
        if cursor:
            try:
                cursor.close()
            except Exception as e:
                logging.error(f"Error closing cursor: {e}")
        if connection:
            try:
                if connection.is_connected():
                    connection.close()
                    logging.info("Database connection closed.")
            except Exception as e:
                logging.error(f"Error closing connection: {e}")


if __name__ == '__main__':
    # Example usage (replace with your actual logic)
    try:
        # Set environment variables (for testing purposes only - use a proper method in production)
        # os.environ["DB_USER"] = "your_db_user"  # Replace with your database username
        # os.environ["DB_PASSWORD"] = "your_db_password"  # Replace with your database password
        # os.environ["DB_NAME"] = "your_db_name" # Replace with your database name
        # Alternatively, use a connection string:
        os.environ["DATABASE_URL"] = "mysql://your_db_user:your_db_password@your_db_host/your_db_name"

        remove_user("testuser123")  # Example: Remove a user named "testuser123"
        print("User removal attempted (check logs for details).")

    except Exception as e:
        print(f"An error occurred: {e}")

