import sqlite3
import subprocess
import shlex
import logging
import re
from email_validator import validate_email, EmailNotValidError
import os  # For database path validation

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def unsubscribe_email(email, db_path="your_database.db", unsubscribe_script_path="/path/to/unsubscribe_script.sh"):
    """
    Checks if an email exists in the database and unsubscribes it if it does.

    Args:
        email (str): The email address to check and unsubscribe.
        db_path (str): The path to the SQLite database file.
        unsubscribe_script_path (str): The path to the unsubscribe script.

    Returns:
        int: 0 if the email doesn't exist or the unsubscribe script fails, 1 if the unsubscribe is successful.
    """

    try:
        # Validate email format
        try:
            emailinfo = validate_email(email, check_deliverability=False)
            email = emailinfo.normalized
        except EmailNotValidError as e:
            logging.warning(f"Invalid email format: {email}. Error: {str(e)}")
            return 0

        # Validate database path
        if not os.path.exists(db_path):
            logging.error(f"Database file not found at: {db_path}")
            return 0

        with sqlite3.connect(db_path) as conn:
            cursor = conn.cursor()

            # Use parameterized query to prevent SQL injection
            cursor.execute("SELECT COUNT(*) FROM users WHERE email = ?", (email,))
            count = cursor.fetchone()[0]

            if count == 0:
                logging.info(f"Email {email} not found in database.")
                return 0  # Email doesn't exist

            # Execute the unsubscribe script with proper quoting and escaping
            # Use shlex.quote to safely escape the email address for the shell
            command = [unsubscribe_script_path, shlex.quote(email)]  # Build the command as a list
            result = subprocess.run(command, capture_output=True, text=True, executable="/bin/bash")

            if result.returncode == 0:
                logging.info(f"Successfully unsubscribed {email}")
                return 1  # Unsubscribe successful
            else:
                logging.error(f"Unsubscribe script failed with error: {result.stderr}")
                return 0  # Unsubscribe script failed

    except sqlite3.Error as e:
        logging.error(f"Database error: {e}")
        return 0
    except FileNotFoundError:
        logging.error(f"Unsubscribe script not found at: {unsubscribe_script_path}")
        return 0
    except Exception as e:
        logging.exception(f"An unexpected error occurred: {e}")  # Use logging.exception to include traceback
        return 0


# Example usage:
if __name__ == "__main__":
    email_to_unsubscribe = "test@example.com"
    result = unsubscribe_email(email_to_unsubscribe)

    if result == 1:
        print(f"Successfully unsubscribed {email_to_unsubscribe}")
    else:
        print(f"Failed to unsubscribe {email_to_unsubscribe}")

