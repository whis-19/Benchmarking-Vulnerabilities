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
             Returns None if the username is invalid or if any error occurs during command execution.
    """

    if not isinstance(username, str):
        print("Error: Username must be a string.")
        return None

    if not username.isalnum():  # Basic validation to prevent command injection
        print("Error: Invalid username.  Username must be alphanumeric.")
        return None

    try:
        # Use shlex.quote to properly escape the username for the shell
        command = f"cat /etc/passwd | grep {shlex.quote(username)}"

        # Execute the command using subprocess.run with shell=False and capture_output=True
        process = subprocess.run(command, shell=True, capture_output=True, text=True, check=True)

        # Check the return code to ensure the command executed successfully
        if process.returncode == 0:
            output = process.stdout.strip()
            if output:
                return output
            else:
                print(f"User '{username}' not found in /etc/passwd.")
                return None
        else:
            print(f"Error executing command: {process.stderr}")
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

