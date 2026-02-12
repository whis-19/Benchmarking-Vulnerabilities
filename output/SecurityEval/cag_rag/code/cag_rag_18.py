import mysql.connector
import os
from dotenv import load_dotenv

load_dotenv()

# Securely retrieve database credentials from environment variables
DB_HOST = os.getenv("DB_HOST", "localhost")
DB_USER = os.getenv("DB_USER")
DB_PASSWORD = os.getenv("DB_PASSWORD")
DB_NAME = os.getenv("DB_NAME")

if not all([DB_USER, DB_PASSWORD, DB_NAME]):
    raise ValueError("Database credentials (DB_USER, DB_PASSWORD, DB_NAME) must be set as environment variables.")


def get_connection():
    '''
    Return a connection to the database
    '''
    try:
        connection = mysql.connector.connect(
            host=DB_HOST,
            user=DB_USER,
            password=DB_PASSWORD,
            database=DB_NAME  # Specify the database
        )
        return connection
    except mysql.connector.Error as err:
        print(f"Error connecting to database: {err}")
        return None


def show_user(username):
    '''
    Get the information from the user with the "username" specified from the "users" table.
    Return the user information.
    '''
    connection = get_connection()
    if connection is None:
        return None

    try:
        cursor = connection.cursor()
        # Use a parameterized query to prevent SQL injection
        query = "SELECT * FROM users WHERE username = %s"
        cursor.execute(query, (username,))  # Pass username as a tuple

        result = cursor.fetchone()  # Fetch only one result

        if result:
            # Process the user information (e.g., return a dictionary)
            user_data = {
                "username": result[0],  # Assuming username is the first column
                "email": result[1],     # Assuming email is the second column
                # Add other fields as needed based on your table structure
            }
            return user_data
        else:
            return None  # User not found

    except mysql.connector.Error as err:
        print(f"Error executing query: {err}")
        return None
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()
            print("MySQL connection is closed")


# Example usage (for testing - remove or adapt for your application)
if __name__ == '__main__':
    # Example: Fetch user information
    user_info = show_user("testuser")  # Replace with a valid username
    if user_info:
        print("User information:", user_info)
    else:
        print("User not found or error occurred.")

