import sqlite3
import subprocess
import shlex
import logging
import re
import os  # For environment variables

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Configuration (using environment variables as an example)
DB_PATH = os.environ.get("UNSUBSCRIBE_DB_PATH", "your_database.db")  # Default value if not set
UNSUBSCRIBE_SCRIPT_PATH = os.environ.get("UNSUBSCRIBE_SCRIPT_PATH", "/path/to/unsubscribe_script.sh")

def unsubscribe_email(email, db_path=DB_PATH, unsubscribe_script_path=UNSUBSCRIBE_SCRIPT_PATH):
    """
    Checks if an email exists in the database and unsubscribes it if it does.

    Args:
        email (str): The email address to check and unsubscribe.
        db_path (str): The path to the SQLite database file.
        unsubscribe_script_path (str): The path to the unsubscribe script.

    Returns:
        int: 0 if the email doesn't exist or the unsubscribe script fails, 1 if the unsubscribe is successful.
    """

    conn = None  # Initialize conn to None for proper cleanup in finally block
    try:
        # Input validation (more robust email format check)
        if not re.match(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", email):
            logging.warning(f"Invalid email format: {email}")
            return 0

        conn = sqlite3.connect(db_path)
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
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, executable="/bin/bash") # Explicitly use bash
        stdout, stderr = process.communicate()
        return_code = process.returncode

        if return_code == 0:
            logging.info(f"Successfully unsubscribed {email}")
            return 1  # Unsubscribe successful
        else:
            logging.error(f"Unsubscribe script failed for {email} with error: {stderr.decode()}")
            return 0  # Unsubscribe script failed

    except sqlite3.IntegrityError as e:
        logging.error(f"Database integrity error: {e}")
        return 0
    except sqlite3.Error as e:
        logging.error(f"Database error: {e}")
        return 0
    except FileNotFoundError:
        logging.error(f"Unsubscribe script not found at: {unsubscribe_script_path}")
        return 0
    except Exception as e:
        logging.exception(f"An unexpected error occurred: {e}")  # Log the full exception traceback
        return 0
    finally:
        if conn:
            conn.close()


# Example usage:
email_to_unsubscribe = "test@example.com"
result = unsubscribe_email(email_to_unsubscribe)

if result == 1:
    print(f"Successfully unsubscribed {email_to_unsubscribe}")
else:
    print(f"Failed to unsubscribe {email_to_unsubscribe}")

