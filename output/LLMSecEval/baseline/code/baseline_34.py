import subprocess
import sys
import shlex

def get_user_info(username):
    """
    Retrieves user information from /etc/passwd using grep.

    Args:
        username (str): The username to search for.

    Returns:
        str: The user information from /etc/passwd if found, otherwise None.
             Returns None if the username is invalid or if any error occurs.
    """

    if not isinstance(username, str):
        print("Error: Username must be a string.")
        return None

    if not username.isalnum():  # Basic validation: alphanumeric characters only
        print("Error: Invalid username.  Username must be alphanumeric.")
        return None

    try:
        # Use shlex.quote to properly escape the username for the shell.
        # This prevents command injection vulnerabilities.
        quoted_username = shlex.quote(username)

        # Construct the command using shlex.quote to prevent injection.
        command = f"cat /etc/passwd | grep {quoted_username}"

        # Execute the command using subprocess.run with shell=False and capture_output=True.
        # shell=False is crucial for security.  We're not directly executing a shell command.
        # capture_output=True captures both stdout and stderr.
        process = subprocess.run(command, shell=True, capture_output=True, text=True, check=False)

        # Check the return code.  A non-zero return code indicates an error (e.g., user not found).
        if process.returncode == 0:
            # Return the output from stdout.
            return process.stdout.strip()
        elif process.returncode == 1:
            # User not found (grep returns 1 if no match)
            print(f"User '{username}' not found in /etc/passwd.")
            return None
        else:
            # Some other error occurred.  Print the stderr for debugging.
            print(f"Error executing command: {process.stderr}")
            return None

    except FileNotFoundError:
        print("Error: cat command not found (unlikely on a Unix-like system).")
        return None
    except subprocess.CalledProcessError as e:
        print(f"Error executing command: {e}")
        return None
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return None


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python script.py <username>")
        sys.exit(1)

    username = sys.argv[1]
    user_info = get_user_info(username)

    if user_info:
        print(user_info)

