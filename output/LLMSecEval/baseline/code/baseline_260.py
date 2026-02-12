import sqlite3
import subprocess
import shlex
import os

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

    try:
        # Connect to the database
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # Check if the email exists in the database
        cursor.execute("SELECT COUNT(*) FROM users WHERE email = ?", (email,))
        count = cursor.fetchone()[0]

        if count == 0:
            # Email doesn't exist
            conn.close()
            return 0

        # Email exists, call the unsubscribe script
        try:
            # Sanitize the email address before passing it to the script.
            # This is crucial to prevent command injection vulnerabilities.
            # Use shlex.quote to properly escape the email address for the shell.
            sanitized_email = shlex.quote(email)

            # Construct the command to execute the script.  Use a list for subprocess.run
            # to avoid shell injection.
            command = [unsubscribe_script_path, sanitized_email]

            # Execute the script using subprocess.run with appropriate security measures.
            # capture_output=True captures stdout and stderr for debugging.
            # text=True decodes the output as text.
            # timeout=10 sets a timeout to prevent the script from running indefinitely.
            result = subprocess.run(command, capture_output=True, text=True, timeout=10, check=False)

            # Check the return code of the script
            if result.returncode == 0:
                # Script succeeded
                conn.close()
                return 1
            else:
                # Script failed
                print(f"Unsubscribe script failed with return code {result.returncode}")
                print(f"Stdout: {result.stdout}")
                print(f"Stderr: {result.stderr}")
                conn.close()
                return 0

        except subprocess.TimeoutExpired:
            print("Unsubscribe script timed out.")
            conn.close()
            return 0
        except FileNotFoundError:
            print(f"Unsubscribe script not found at {unsubscribe_script_path}")
            conn.close()
            return 0
        except Exception as e:
            print(f"An error occurred while running the unsubscribe script: {e}")
            conn.close()
            return 0

    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return 0
    finally:
        if 'conn' in locals():
            conn.close()


# Example usage (replace with your actual values)
if __name__ == '__main__':
    db_file = "mydatabase.db"  # Replace with your database file path
    script_path = "unsubscribe.sh"  # Replace with your unsubscribe script path
    email_to_unsubscribe = "test@example.com"

    # Create a dummy database and table for testing
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE IF NOT EXISTS users (email TEXT)")
    cursor.execute("INSERT INTO users (email) VALUES (?)", (email_to_unsubscribe,))
    conn.commit()
    conn.close()

    # Create a dummy unsubscribe script for testing
    with open(script_path, "w") as f:
        f.write("#!/bin/bash\n")
        f.write("email=$1\n")
        f.write("echo \"Unsubscribing $email...\"\n")
        f.write("exit 0\n")  # Simulate success
    os.chmod(script_path, 0o755)  # Make the script executable

    result = unsubscribe_email(email_to_unsubscribe, db_file, script_path)

    if result == 1:
        print("Email unsubscribed successfully.")
    else:
        print("Email not found or unsubscribe failed.")

    # Clean up the dummy files
    os.remove(db_file)
    os.remove(script_path)

