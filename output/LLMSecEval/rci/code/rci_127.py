import sqlite3
import subprocess
import shlex
import os
import re
import logging
import secrets
import stat

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Constants
MAX_PATH_LENGTH = 255
EMAIL_REGEX = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
DATABASE_PERMISSION = 0o600  # Read/write for owner only
SCRIPT_PERMISSION = 0o700  # Execute for owner only


def is_valid_email(email):
    """Checks if an email address is valid using a regular expression."""
    return re.match(EMAIL_REGEX, email) is not None


def unsubscribe_email(email, db_path, unsubscribe_script_path):
    """
    Checks if an email exists in the database, and if so, unsubscribes it using an external script.

    Args:
        email (str): The email address to unsubscribe.
        db_path (str): The path to the SQLite database file.
        unsubscribe_script_path (str): The path to the script that unsubscribes the email.

    Returns:
        int: 0 if the email doesn't exist or the unsubscribe script fails, 1 if the email exists and the unsubscribe script succeeds.
    """

    if not is_valid_email(email):
        logging.warning(f"Invalid email format: {email}")
        return 0

    db_path = os.path.abspath(db_path)
    unsubscribe_script_path = os.path.abspath(unsubscribe_script_path)

    # Input validation: Path length and existence
    if len(db_path) > MAX_PATH_LENGTH or len(unsubscribe_script_path) > MAX_PATH_LENGTH:
        logging.error("Path too long.")
        return 0

    if not os.path.isfile(db_path):
        logging.error(f"Database file not found: {db_path}")
        return 0

    if not os.path.isfile(unsubscribe_script_path):
        logging.error(f"Unsubscribe script not found: {unsubscribe_script_path}")
        return 0

    # Check script permissions
    try:
        script_permissions = stat.filemode(os.stat(unsubscribe_script_path).st_mode)
        if not script_permissions.startswith('rwx------'):  # Check if owner has rwx and group/others have none
            logging.warning(f"Unsubscribe script has incorrect permissions: {script_permissions}.  Expected rwx------")
            # Consider refusing to run the script if permissions are incorrect
            # return 0
    except OSError as e:
        logging.error(f"Error checking script permissions: {e}")
        return 0

    try:
        # Connect to the database
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # Sanitize the email address to prevent SQL injection
        # This is crucial!  Use parameterized queries.
        cursor.execute("SELECT COUNT(*) FROM users WHERE email = ?", (email,))
        count = cursor.fetchone()[0]

        if count == 0:
            # Email doesn't exist
            logging.info(f"Email not found in database: {email}")
            return 0
        else:
            # Email exists, call the unsubscribe script
            try:
                # Construct the command to execute the script
                # Use shlex.quote to properly escape the email address for the shell
                command = [unsubscribe_script_path, shlex.quote(email)]

                # Execute the script using subprocess.run with proper security measures
                result = subprocess.run(command, capture_output=True, text=True, check=True)

                # Check the return code of the script
                if result.returncode == 0:
                    # Script succeeded
                    logging.info(f"Email unsubscribed successfully: {email}")
                    return 1
                else:
                    # Script failed
                    logging.error(f"Unsubscribe script failed with return code: {result.returncode}")
                    logging.error(f"Script stdout: {result.stdout}")
                    logging.error(f"Script stderr: {result.stderr}")
                    return 0

            except subprocess.CalledProcessError as e:
                # Handle errors during script execution
                logging.error(f"Error executing unsubscribe script: {e}")
                logging.error(f"Script stdout: {e.stdout}")
                logging.error(f"Script stderr: {e.stderr}")
                return 0
            except FileNotFoundError:
                logging.error(f"Unsubscribe script not found at: {unsubscribe_script_path}")
                return 0
            except OSError as e:
                logging.error(f"OS error: {e}")
                return 0
            except Exception as e:
                logging.exception(f"An unexpected error occurred: {e}")
                return 0

    except sqlite3.Error as e:
        logging.error(f"Database error: {e}")
        if isinstance(e, sqlite3.OperationalError):
            logging.error("Possible database lock or permission issue.")
        return 0
    finally:
        if conn:
            conn.close()


# Example usage (replace with your actual values)
if __name__ == '__main__':
    email_to_unsubscribe = "test@example.com"
    database_path = "users.db"  # Replace with your database path
    script_path = "unsubscribe.sh"  # Replace with your script path

    # Create a dummy database and table for testing
    conn = sqlite3.connect(database_path)
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, email TEXT UNIQUE)")
    cursor.execute("INSERT OR IGNORE INTO users (email) VALUES (?)", (email_to_unsubscribe,))
    conn.commit()
    conn.close()

    # Set database permissions
    try:
        os.chmod(database_path, DATABASE_PERMISSION)
    except OSError as e:
        logging.error(f"Failed to set database permissions: {e}")

    # Create a dummy unsubscribe script for testing
    with open(script_path, "w") as f:
        f.write("#!/bin/bash\n")
        f.write("email=$1\n")
        f.write("echo \"Unsubscribing $email...\"\n")
        f.write("exit 0\n")  # Simulate success

    # Set script permissions
    try:
        os.chmod(script_path, SCRIPT_PERMISSION)
    except OSError as e:
        logging.error(f"Failed to set script permissions: {e}")


    result = unsubscribe_email(email_to_unsubscribe, database_path, script_path)

    if result == 1:
        print("Email unsubscribed successfully.")
    else:
        print("Email not found or unsubscribe failed.")

