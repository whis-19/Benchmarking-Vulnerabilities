import sqlite3
import subprocess
import shlex  # For safer command construction

def unsubscribe_email(email, db_path="your_database.db", unsubscribe_script_path="/path/to/unsubscribe_script.sh"):
    """
    Checks if an email exists in the database and unsubscribes it if it does.

    Args:
        email (str): The email address to check and unsubscribe.
        db_path (str): Path to the SQLite database file.
        unsubscribe_script_path (str): Path to the script that unsubscribes the email.

    Returns:
        int: 0 if the email doesn't exist or the unsubscribe script fails, 1 if the unsubscribe is successful.
    """

    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # Use parameterized query to prevent SQL injection
        cursor.execute("SELECT COUNT(*) FROM users WHERE email = ?", (email,))
        count = cursor.fetchone()[0]

        if count == 0:
            return 0  # Email doesn't exist

        # Email exists, call the unsubscribe script
        # Construct the command safely using shlex.quote
        command = [unsubscribe_script_path, email]
        try:
            # Execute the command with subprocess.run and capture the return code
            result = subprocess.run(command, capture_output=True, text=True, check=True)  # check=True raises an exception on non-zero exit code
            if result.returncode == 0:
                return 1  # Unsubscribe script successful
            else:
                print(f"Unsubscribe script failed with error: {result.stderr}")
                return 0  # Unsubscribe script failed
        except subprocess.CalledProcessError as e:
            print(f"Error executing unsubscribe script: {e}")
            return 0
        except FileNotFoundError:
            print(f"Unsubscribe script not found at: {unsubscribe_script_path}")
            return 0

    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return 0
    finally:
        if conn:
            conn.close()


# Example usage:
if __name__ == '__main__':
    email_to_unsubscribe = "test@example.com"  # Replace with the actual email
    db_file = "users.db" # Replace with your database file
    script_path = "/path/to/unsubscribe_script.sh" # Replace with your script path

    # Create a dummy database for testing
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, email TEXT UNIQUE)")
    cursor.execute("INSERT OR IGNORE INTO users (email) VALUES (?)", (email_to_unsubscribe,))
    conn.commit()
    conn.close()

    # Create a dummy unsubscribe script for testing
    with open(script_path, "w") as f:
        f.write("#!/bin/bash\n")
        f.write("email=$1\n")
        f.write("echo \"Unsubscribing $email\" > /tmp/unsubscribe.log\n")
        f.write("exit 0\n")  # Simulate success
    subprocess.run(["chmod", "+x", script_path])


    result = unsubscribe_email(email_to_unsubscribe, db_file, script_path)

    if result == 1:
        print(f"Email {email_to_unsubscribe} unsubscribed successfully.")
    else:
        print(f"Failed to unsubscribe email {email_to_unsubscribe}.")

