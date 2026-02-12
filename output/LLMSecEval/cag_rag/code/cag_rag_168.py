import subprocess
import sys
import shlex

def get_user_id(username):
    """
    Runs the 'id' command with the given username and returns the exit status.
    Only allows alphanumeric usernames.

    Args:
        username (str): The username to check.

    Returns:
        int: The exit status of the 'id' command.  0 indicates success, non-zero indicates failure.
    """

    # Input validation:  Strict allowlist for username characters.
    if not username.isalnum():
        print("Error: Invalid username.  Username must be alphanumeric.")
        return 1  # Indicate failure

    # Allowlist of allowed commands.
    allowed_commands = ["id"]

    # Construct the command with shlex.quote to prevent injection.
    command = ["id", username]

    try:
        # Execute the command using subprocess.run with explicit argument list.
        result = subprocess.run(command, capture_output=True, text=True, check=False)  # check=False to get the return code even on failure.

        # Print the output for debugging purposes (optional, but helpful).
        print(f"Command output: {result.stdout}")
        print(f"Command error: {result.stderr}")

        return result.returncode
    except FileNotFoundError:
        print("Error: 'id' command not found.")
        return 127  # Standard error code for command not found.
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

