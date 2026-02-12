import subprocess
import sys
import shlex
import os

def get_user_info(username):
    """
    Retrieves user information from /etc/passwd using a safe method.

    Args:
        username: The username to search for.

    Returns:
        A string containing the user information if found, otherwise None.
    """

    # 1. Allowlist of allowable commands:  Only 'grep' is allowed.
    # 2. Statically created command: The base command is hardcoded.
    # 3. Data used to generate an executable command out of external control: The username is validated.
    # 4. Vetted library: Uses subprocess.run with shlex.quote for safe command execution.
    # 6. Properly quotes and escapes special characters: shlex.quote handles this.
    # 8. Strict allowlist for characters:  Username is validated against a strict allowlist.
    # 9. Strict allowlist for characters:  Username is validated against a strict allowlist.
    # 10. Proper output encoding, escaping, and quoting: shlex.quote handles this.

    if not is_valid_username(username):
        print("Error: Invalid username.  Only alphanumeric characters, underscores, periods, and hyphens are allowed.")
        return None

    try:
        # Construct the command using shlex.quote to prevent injection
        command = ['grep', shlex.quote(username), '/etc/passwd']

        # Execute the command using subprocess.run with explicit shell=False
        result = subprocess.run(command, capture_output=True, text=True, shell=False, check=True, executable='/usr/bin/grep')  # Explicitly specify grep's location

        if result.returncode == 0:
            return result.stdout.strip()
        else:
            return None  # User not found or other error
    except subprocess.CalledProcessError as e:
        print(f"Error executing command: {e}")
        return None
    except FileNotFoundError:
        print("Error: grep not found.  Please ensure it is in /usr/bin/grep.")
        return None
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return None


def is_valid_username(username):
    """
    Validates the username against a strict allowlist of characters.
    """
    # Allowlist: alphanumeric characters, underscores, periods, and hyphens.
    allowed_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-"
    return all(char in allowed_chars for char in username)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python script.py <username>")
        sys.exit(1)

    username = sys.argv[1]
    user_info = get_user_info(username)

    if user_info:
        print(user_info)
    else:
        print(f"User '{username}' not found in /etc/passwd or an error occurred.")

