import subprocess
import sys
import os

def get_user_id_status(username):
    """
    Runs the 'id' command with the given username and returns the exit status.

    This function uses a strict allowlist for the username to prevent command injection.
    It also uses subprocess.run with shell=False to avoid shell injection vulnerabilities.
    """

    # 1. Allowlist of allowable commands
    allowed_commands = ["id"]

    # 2. Statically created command (base command)
    command = "id"

    # 3. Data used to generate an executable command out of external control.
    #    The username is validated against a strict allowlist.

    MAX_USERNAME_LENGTH = 32  # Or a reasonable value

    # 8, 9, 10. Strict allowlist for username characters.  Only allow alphanumeric characters.
    if not all(c.isalnum() for c in username):
        print("Error: Invalid username. Only alphanumeric characters are allowed.")
        return 1  # Return non-zero exit status to indicate failure

    if len(username) > MAX_USERNAME_LENGTH:
        print(f"Error: Username exceeds maximum length of {MAX_USERNAME_LENGTH} characters.")
        return 1

    # 4. Vetted library (subprocess) used to prevent OS command injection.
    #    shell=False is crucial to prevent shell injection.
    try:
        result = subprocess.run([command, username], capture_output=True, text=True, check=False, encoding='utf-8')

        # Consider Logging
        # Be careful not to log sensitive information.
        # print(f"DEBUG: Username: {username}, Exit Status: {result.returncode}") # Example logging

        return result.returncode
    except FileNotFoundError:
        # The 'id' command is not in the system's PATH.
        print(f"Error: Command '{command}' not found.")
        return 127  # Standard exit code for command not found
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return 1  # Return non-zero exit status to indicate failure

    # Hypothetical: If we allowed other commands, we'd need to validate them too.
    # For example, if we allowed 'whoami', we wouldn't need to validate the username.
    # But if we allowed 'ls', we'd need to carefully validate the directory path.

    # While the alphanumeric allowlist and `shell=False` provide strong protection,
    # it's important to consider other potential attack vectors and implement a
    # defense-in-depth strategy.


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python script.py <username>")
        sys.exit(1)

    username = sys.argv[1]
    exit_status = get_user_id_status(username)
    print(f"Exit status: {exit_status}")
    sys.exit(exit_status)

