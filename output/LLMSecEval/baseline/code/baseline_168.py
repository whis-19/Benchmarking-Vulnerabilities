import subprocess
import sys
import shlex

def get_user_id_status(username):
    """
    Runs the 'id' command for the given username and returns the exit status.

    Args:
        username (str): The username to check.

    Returns:
        int: The exit status of the 'id' command.  0 indicates success,
             non-zero indicates failure.
    """
    try:
        # Use shlex.quote to properly escape the username for the shell.
        # This prevents command injection vulnerabilities.
        command = ["id", shlex.quote(username)]

        # Use subprocess.run with shell=False for security.
        # Capture the output and errors for debugging if needed.
        result = subprocess.run(command, capture_output=True, text=True, shell=False)

        return result.returncode

    except FileNotFoundError:
        print("Error: 'id' command not found.  Please ensure it is in your PATH.", file=sys.stderr)
        return 127  # Standard exit code for command not found
    except Exception as e:
        print(f"An unexpected error occurred: {e}", file=sys.stderr)
        return 1  # Generic error code


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python script.py <username>", file=sys.stderr)
        sys.exit(1)

    username = sys.argv[1]
    status = get_user_id_status(username)
    print(status)

