import subprocess
import sys
import shlex
import re  # For input validation
import logging  # For logging

# Configure logging (adjust level as needed)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


MAX_USERNAME_LENGTH = 256  # Define a reasonable maximum username length
USERNAME_REGEX = r"^[a-zA-Z0-9_-]+$"  # Example: alphanumeric, underscore, hyphen

def get_user_id_status(username):
    """
    Runs the 'id' command for the given username and returns the exit status.

    Args:
        username (str): The username to check.

    Returns:
        int: The exit status of the 'id' command.  0 indicates success,
             non-zero indicates failure.
    """
    if len(username) > MAX_USERNAME_LENGTH:
        logging.error(f"Username exceeds maximum length of {MAX_USERNAME_LENGTH} characters.")
        return 1  # Or another appropriate error code

    if not re.match(USERNAME_REGEX, username):
        logging.error(f"Invalid username format.  Must match: {USERNAME_REGEX}")
        return 1  # Or another appropriate error code


    try:
        # Use shlex.quote to properly escape the username for the shell.
        # This prevents command injection vulnerabilities.
        command = ["id", shlex.quote(username)]

        # Use subprocess.run with shell=False for security.
        # Capture the output and errors for debugging (optional).
        result = subprocess.run(command, capture_output=True, text=True, shell=False)

        logging.debug(f"'id' command output: {result.stdout}")  # Log the output for debugging
        logging.debug(f"'id' command errors: {result.stderr}")  # Log the errors for debugging

        return result.returncode

    except FileNotFoundError:
        logging.error("'id' command not found.  Please ensure it is in your PATH.")
        return 127  # Standard exit code for command not found
    except Exception as e:
        logging.exception(f"An unexpected error occurred: {e}")  # Log the full exception
        return 1  # Generic error code


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python script.py <username>", file=sys.stderr)
        sys.exit(1)

    username = sys.argv[1]
    status = get_user_id_status(username)
    print(status)
    sys.exit(status) # Exit with the same status code as the id command

