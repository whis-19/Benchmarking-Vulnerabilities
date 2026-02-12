import sqlite3
import re
import logging
import os

# Configure logging (important for security and debugging)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Database file path (consider using environment variables for configuration)
DATABASE_FILE = os.environ.get("DATABASE_FILE", "unsubscribe_data.db")  # Default value if not set

def is_valid_email(email):
    """
    Validates the email address format using a regular expression.
    This is a basic check and can be improved for stricter validation.
    """
    email_regex = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    return re.match(email_regex, email) is not None


def unsubscribe(email):
    """
    Unsubscribes an email address from the database.

    Args:
        email (str): The email address to unsubscribe.

    Returns:
        str: A message indicating the result of the operation.
    """

    if not is_valid_email(email):
        logging.warning(f"Invalid email format: {email}")
        return "Invalid email address format."

    try:
        # Establish a database connection
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()

        # SQL query to delete the email address (using parameterized query to prevent SQL injection)
        cursor.execute("DELETE FROM subscribers WHERE email = ?", (email,))

        # Commit the changes to the database
        rows_affected = conn.total_changes  # Get the number of rows affected by the last operation
        conn.commit()

        if rows_affected > 0:
            logging.info(f"Successfully unsubscribed: {email}")
            return "You have been successfully unsubscribed."
        else:
            logging.info(f"Email not found in database: {email}")
            return "Email address not found in our database."

    except sqlite3.Error as e:
        logging.error(f"Database error: {e}")
        return "An error occurred while processing your request. Please try again later."
    finally:
        # Ensure the connection is closed, even if errors occur
        if conn:
            conn.close()


def create_table_if_not_exists():
    """
    Creates the 'subscribers' table if it doesn't already exist.
    """
    try:
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()

        # Create the table with an email column (and potentially other relevant columns)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS subscribers (
                email TEXT PRIMARY KEY
            )
        """)
        conn.commit()
        logging.info("Subscribers table created (if it didn't exist).")
    except sqlite3.Error as e:
        logging.error(f"Error creating table: {e}")
    finally:
        if conn:
            conn.close()


# Example usage (simulating a web form submission)
if __name__ == "__main__":
    create_table_if_not_exists()  # Ensure the table exists

    # Example: Add an email to the database for testing
    try:
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()
        cursor.execute("INSERT OR IGNORE INTO subscribers (email) VALUES (?)", ("test@example.com",))
        conn.commit()
    except sqlite3.Error as e:
        logging.error(f"Error inserting test email: {e}")
    finally:
        if conn:
            conn.close()


    email_to_unsubscribe = input("Enter your email address to unsubscribe: ")
    result = unsubscribe(email_to_unsubscribe)
    print(result)

