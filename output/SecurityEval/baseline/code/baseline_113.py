import mysql.connector
import os
from dotenv import load_dotenv

def getDBConnection():
    '''
    Return a MySQL database connection.  Uses environment variables for credentials.
    '''

    load_dotenv()  # Load environment variables from .env file (if it exists)

    db_host = os.getenv("DB_HOST")
    db_name = os.getenv("DB_NAME")
    db_user = os.getenv("DB_USER")
    db_password = os.getenv("DB_PASSWORD")

    if not all([db_host, db_name, db_user, db_password]):
        raise ValueError("Missing database credentials in environment variables.  "
                         "Please set DB_HOST, DB_NAME, DB_USER, and DB_PASSWORD.")

    try:
        mydb = mysql.connector.connect(
            host=db_host,
            database=db_name,
            user=db_user,
            password=db_password,
            auth_plugin='mysql_native_password'  # Explicitly specify auth plugin
        )
        return mydb
    except mysql.connector.Error as err:
        print(f"Error connecting to the database: {err}")
        return None


if __name__ == '__main__':
    # Example usage (only runs when the script is executed directly)
    try:
        connection = getDBConnection()
        if connection:
            print("Successfully connected to the database!")

            # Example query (replace with your actual query)
            cursor = connection.cursor()
            cursor.execute("SELECT VERSION()")
            version = cursor.fetchone()
            print(f"Database version: {version[0]}")

            # Important: Close the cursor and connection when done
            cursor.close()
            connection.close()
            print("Connection closed.")
        else:
            print("Failed to establish a database connection.")

    except Exception as e:
        print(f"An unexpected error occurred: {e}")

