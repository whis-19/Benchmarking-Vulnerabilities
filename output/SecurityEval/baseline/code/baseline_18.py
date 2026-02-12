import mysql.connector
import os
from dotenv import load_dotenv

load_dotenv()

def get_connection():
    '''
    Return a connection to the database
    '''
    try:
        connection = mysql.connector.connect(
            host=os.getenv("DB_HOST", "localhost"),  # Default to localhost if not in .env
            user=os.getenv("DB_USER"),
            password=os.getenv("DB_PASSWORD"),
            database=os.getenv("DB_NAME")  # Add database name
        )
        return connection
    except mysql.connector.Error as err:
        print(f"Error connecting to database: {err}")
        return None


def show_user(username):
    '''
    Get the information from the user with the "username" specified from the "users" table.
    Return the user information.  Returns None if user not found or error occurs.
    '''
    connection = get_connection()
    if connection is None:
        return None

    try:
        cursor = connection.cursor()
        query = "SELECT id, username, email, created_at FROM users WHERE username = %s"  # Explicitly select columns
        cursor.execute(query, (username,))  # Use parameterized query to prevent SQL injection
        result = cursor.fetchone()  # Fetch only one result

        if result:
            # Convert the result to a dictionary for easier access and safer handling
            user_data = {
                "id": result[0],
                "username": result[1],
                "email": result[2],
                "created_at": result[3]
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


if __name__ == '__main__':
    # Example Usage (after setting up your .env file and database)
    user_info = show_user("testuser")  # Replace with an actual username in your database

    if user_info:
        print("User Information:")
        print(f"ID: {user_info['id']}")
        print(f"Username: {user_info['username']}")
        print(f"Email: {user_info['email']}")
        print(f"Created At: {user_info['created_at']}")
    else:
        print("User not found or an error occurred.")

