import sqlite3
import subprocess
import os
import re

def unsubscribe_email(email, db_path, unsubscribe_script_path):
    """
    Checks if an email exists in the database and unsubscribes it if it does.

    Args:
        email (str): The email address to unsubscribe.
        db_path (str): The path to the SQLite database.
        unsubscribe_script_path (str): The path to the script that unsubscribes the email.

    Returns:
        int: 0 if the email doesn't exist or the unsubscribe script fails, 1 if the unsubscribe is successful.
    """

    # Input validation: Email format check
    if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
        print("Error: Invalid email format.")
        return 0

    # Input validation: Check if paths are safe (basic check, can be improved)
    if not (os.path.abspath(db_path).startswith(os.path.abspath(".")) and os.path.isfile(db_path)):
        print("Error: Invalid database path.")
        return 0

    if not (os.path.abspath(unsubscribe_script_path).startswith(os.path.abspath(".")) and os.path.isfile(unsubscribe_script_path) and os.access(unsubscribe_script_path, os.X_OK)):
        print("Error: Invalid unsubscribe script path or not executable.")
        return 0

    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # Use parameterized query to prevent SQL injection
        cursor.execute("SELECT COUNT(*) FROM users WHERE email = ?", (email,))
        count = cursor.fetchone()[0]

        if count == 0:
            print("Email not found in the database.")
            return 0
        else:
            # Execute the unsubscribe script with proper quoting
            try:
                # Construct the command with proper quoting
                command = [unsubscribe_script_path, email]
                process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, executable=unsubscribe_script_path) # Directly execute the script
                stdout, stderr = process.communicate()
                return_code = process.returncode

                if return_code == 0:
                    print("Email unsubscribed successfully.")
                    return 1
                else:
                    print(f"Unsubscribe script failed with error code {return_code}: {stderr.decode()}")
                    return 0
            except subprocess.CalledProcessError as e:
                print(f"Error executing unsubscribe script: {e}")
                return 0
            except FileNotFoundError:
                print("Error: Unsubscribe script not found.")
                return 0

    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return 0
    finally:
        if conn:
            conn.close()

if __name__ == '__main__':
    # Example usage (replace with your actual values)
    db_file = "users.db"  # Example database file
    unsubscribe_script = "unsubscribe.sh"  # Example script path

    # Create a dummy database and table for testing
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, email TEXT UNIQUE)")
    cursor.execute("INSERT OR IGNORE INTO users (email) VALUES ('test@example.com')")
    conn.commit()
    conn.close()

    # Create a dummy unsubscribe script
    with open(unsubscribe_script, "w") as f:
        f.write("#!/bin/bash\n")
        f.write("email=$1\n")
        f.write("echo \"Unsubscribing $email\" >> unsubscribe_log.txt\n")
        f.write("exit 0\n")  # Simulate success
    os.chmod(unsubscribe_script, 0o755)  # Make the script executable

    email_to_unsubscribe = "test@example.com"
    result = unsubscribe_email(email_to_unsubscribe, db_file, unsubscribe_script)
    print(f"Unsubscribe result: {result}")

    email_to_unsubscribe = "nonexistent@example.com"
    result = unsubscribe_email(email_to_unsubscribe, db_file, unsubscribe_script)
    print(f"Unsubscribe result: {result}")

