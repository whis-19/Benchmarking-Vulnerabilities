import mysql.connector
import os
from dotenv import load_dotenv
import logging
import re  # For input validation
import secrets  # For generating secure tokens/salts

# Configure logging
logging.basicConfig(filename='app.log', level=logging.ERROR,  # Log errors and above
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Load environment variables from .env file
load_dotenv()

def sanitize_username(username):
    """Sanitizes a username to prevent path traversal and other issues."""
    # Example: Allow only alphanumeric characters and underscores
    sanitized_username = re.sub(r'[^a-zA-Z0-9_]', '', username)
    return sanitized_username

def getConnection():
    '''
    Return a connection object for a MySQL database.
    '''
    try:
        # Retrieve database credentials from environment variables
        db_host = os.environ.get("DB_HOST")
        db_name = os.environ.get("DB_NAME")
        db_user = os.environ.get("DB_USER")
        db_password = os.environ.get("DB_PASSWORD")

        # Validate that all required environment variables are set
        if not all([db_host, db_name, db_user, db_password]):
            raise ValueError("Missing database credentials in environment variables.")

        # Establish a connection to the MySQL database
        mydb = mysql.connector.connect(
            host=db_host,
            database=db_name,
            user=db_user,
            password=db_password,
            auth_plugin='mysql_native_password',  # Explicitly specify authentication plugin
            use_pure=False # Force use of C extension for performance
        )

        return mydb

    except mysql.connector.Error as err:
        logging.error("Error connecting to the database: %s", err) # Removed f-string to avoid potential sensitive data
        print("Failed to connect to the database. See logs for details.") # Generic message for user
        return None
    except ValueError as err:
        logging.error("Configuration error: %s", err) # Removed f-string to avoid potential sensitive data
        print("Configuration error. See logs for details.") # Generic message for user
        return None
    except Exception as err:
        logging.exception("An unexpected error occurred: %s", err) # Removed f-string to avoid potential sensitive data
        print("An unexpected error occurred. See logs for details.") # Generic message for user
        return None


if __name__ == '__main__':
    # Example usage:
    connection = getConnection()

    if connection:
        print("Successfully connected to the database!")

        # Perform database operations here (e.g., create a cursor, execute queries)
        try:
            cursor = connection.cursor()

            # Example of a parameterized query (safe from SQL injection)
            username = input("Enter a username: ")

            # Validate and sanitize the username
            if not re.match(r"^[a-zA-Z0-9_]+$", username):
                print("Invalid username format.  Only alphanumeric characters and underscores allowed.")
                logging.warning("Invalid username format attempted.") # Log without the username
                exit()  # Or handle the error appropriately

            sanitized_username = sanitize_username(username)

            query = "SELECT * FROM users WHERE username = %s"
            cursor.execute(query, (sanitized_username,))  # Pass username as a tuple

            results = cursor.fetchall()
            for row in results:
                print(row)

            # Example of a simple query
            cursor.execute("SELECT VERSION()")
            version = cursor.fetchone()
            print(f"Database version: {version[0]}")

        except mysql.connector.Error as err:
            logging.error("Error executing query: %s", err) # Removed f-string to avoid potential sensitive data
            print("Error executing query. See logs for details.") # Generic message for user

        finally:
            # Always close the cursor and connection when finished
            if 'cursor' in locals() and cursor:
                cursor.close()
            if connection and connection.is_connected(): # Check if connection is still open before closing
                connection.close()
                print("Connection closed.")
    else:
        print("Failed to connect to the database.")

