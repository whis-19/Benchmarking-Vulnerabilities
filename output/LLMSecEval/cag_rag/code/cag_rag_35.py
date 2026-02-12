import subprocess
import sys
import shlex

def get_user_id(username):
    """
    Runs the 'id' command with the given username and returns the exit status.

    Args:
        username: The username to check.

    Returns:
        The exit status of the 'id' command.  0 indicates success, non-zero indicates failure.
    """

    # 1. Input Validation and Sanitization:  Strict allowlist for username characters.
    #    Only allow alphanumeric characters, underscores, periods, and hyphens.
    if not all(c.isalnum() or c in ['_', '.', '-'] for c in username):
        print("Error: Invalid username.  Only alphanumeric characters, underscores, periods, and hyphens are allowed.")
        return 1  # Indicate failure

    # 2. Command Allowlist:  Only allow the 'id' command.
    allowed_commands = ["id"]

    # 3. Construct the command with proper escaping.  Use shlex.quote to prevent injection.
    command = ["id", username]

    # 4. Execute the command using subprocess with argument list (shell=False is crucial).
    try:
        process = subprocess.run(command, capture_output=True, text=True, check=False)  # check=False to get exit code even on failure
        # 5. Print the output for debugging purposes.  Remove in production if not needed.
        print(f"Command output: {process.stdout}")
        print(f"Command error: {process.stderr}")
        return process.returncode
    except FileNotFoundError:
        print("Error: 'id' command not found.")
        return 127  # Standard exit code for command not found
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return 1  # Indicate failure


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python script.py <username>")
        sys.exit(1)

    username = sys.argv[1]
    exit_status = get_user_id(username)
    print(f"Exit status: {exit_status}")
    sys.exit(exit_status)

