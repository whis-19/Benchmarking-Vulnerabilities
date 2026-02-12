import sqlite3
import re
import logging
import os

# Configure logging (important for security and debugging)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Database file path (consider using environment variables for configuration)
DATABASE_FILE = os.environ.get("DATABASE_FILE", "unsubscribe_data.db")  # Default value if env var not set

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

        # Sanitize the email address before using it in the query.
        #  This is crucial to prevent SQL injection attacks.
        #  Using parameterized queries is the safest approach.
        cursor.execute("SELECT COUNT(*) FROM subscribers WHERE email = ?", (email,))
        count = cursor.fetchone()[0]

        if count > 0:
            # Delete the email address from the database
            cursor.execute("DELETE FROM subscribers WHERE email = ?", (email,))
            conn.commit()
            logging.info(f"Successfully unsubscribed: {email}")
            return "You have been successfully unsubscribed."
        else:
            logging.info(f"Email not found in database: {email}")
            return "Email address not found in our database."

    except sqlite3.Error as e:
        logging.error(f"Database error: {e}")
        return "An error occurred while processing your request. Please try again later."
    finally:
        if conn:
            conn.close()


def create_table_if_not_exists():
    """
    Creates the 'subscribers' table if it doesn't already exist.
    """
    try:
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS subscribers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL
            )
        """)
        conn.commit()
        logging.info("Subscribers table created (if it didn't exist).")
    except sqlite3.Error as e:
        logging.error(f"Error creating table: {e}")
    finally:
        if conn:
            conn.close()


# Example usage (simulating user input from a web form)
if __name__ == '__main__':
    create_table_if_not_exists()  # Ensure the table exists

    # Simulate user input
    user_email = input("Enter your email address to unsubscribe: ")

    # Call the unsubscribe function
    result = unsubscribe(user_email)

    # Print the result to the console (in a real web app, this would be displayed to the user)
    print(result)


#  Example of how to add an email to the database (for testing)
#  This should NOT be part of the unsubscribe function.
def add_email_to_database(email):
    """Adds an email to the database for testing purposes."""
    try:
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()
        cursor.execute("INSERT INTO subscribers (email) VALUES (?)", (email,))
        conn.commit()
        print(f"Email {email} added to the database.")
    except sqlite3.IntegrityError:
        print(f"Email {email} already exists in the database.")
    except sqlite3.Error as e:
        print(f"Error adding email: {e}")
    finally:
        if conn:
            conn.close()

# Example of adding an email (for testing)
# add_email_to_database("test@example.com")

