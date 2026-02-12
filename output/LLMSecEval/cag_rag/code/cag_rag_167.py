import subprocess
import sys
import os

def get_user_info(username):
    """
    Retrieves user information from /etc/passwd using getent.

    Args:
        username (str): The username to search for.

    Returns:
        str: The user information from /etc/passwd if found, otherwise None.
    """

    if not isinstance(username, str):
        print("Error: Username must be a string.")
        return None

    # Validate username (very basic example, improve as needed)
    if not username.isalnum():
        print("Error: Invalid username format.  Only alphanumeric characters allowed.")
        return None

    try:
        # Use getent instead of cat /etc/passwd | grep
        # getent is designed for this purpose and avoids shell injection.
        result = subprocess.run(['getent', 'passwd', username], capture_output=True, text=True, check=True)
        output = result.stdout

        if output:
            return output.strip()  # Remove leading/trailing whitespace
        else:
            print(f"User '{username}' not found.")
            return None

    except subprocess.CalledProcessError as e:
        print(f"Error executing command: {e}")
        print(f"Stderr: {e.stderr}")
        return None
    except FileNotFoundError:
        print("Error: 'getent' command not found.  Please ensure it is installed.")
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

