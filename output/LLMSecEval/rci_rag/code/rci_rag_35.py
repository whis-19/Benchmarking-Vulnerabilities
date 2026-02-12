import subprocess
import sys
import shlex
import logging
import os
import shutil

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Dedicated user for running the id command (replace with actual user)
ID_USER = "id_user"  # Replace with the actual dedicated user

def get_user_id(username):
    """
    Runs the 'id' command with the given username and returns the exit status.

    Args:
        username: The username to check.  Must be a safe username.

    Returns:
        The exit status of the 'id' command.  0 indicates success, non-zero indicates failure.
    """

    # 1. Allowlist of allowable commands:  Only allow 'id' command.
    allowed_commands = ["id"]

    # 2. Statically created command: The base command is static.
    command = "id"

    # 3. Data used to generate an executable command out of external control:
    #    The username is validated to prevent command injection.

    # 8, 9, 10. Strict allowlist for characters in username:
    #    Only allow alphanumeric characters, underscores, periods, and hyphens.
    if not all(c.isalnum() or c in "._-" for c in username):
        logging.error(f"Invalid username: {username}. Only alphanumeric characters, underscores, periods, and hyphens are allowed.")
        print("Error: Invalid username. Only alphanumeric characters, underscores, periods, and hyphens are allowed.")
        return 1  # Indicate failure

    # 6. Properly quote and escape special characters (using shlex.quote):
    #    Although the allowlist *should* prevent injection, quoting is still good practice.
    quoted_username = shlex.quote(username)

    # Construct the full command with the validated and quoted username.
    full_command = [command, quoted_username]

    # Optional: Enforce the allowed_commands list
    if command not in allowed_commands:
        logging.error(f"Command not allowed: {command}")
        print("Error: Command not allowed.")
        return 1

    try:
        # 4. Vetted library (subprocess) to prevent OS command injection.
        #    Use subprocess.run with a list of arguments to avoid shell injection.

        # Attempt to run as the dedicated user using sudo
        if ID_USER:
            full_command = ["sudo", "-u", ID_USER] + full_command
            logging.debug(f"Running command with sudo: {full_command}")

        result = subprocess.run(full_command, capture_output=True, text=True, check=False)  # check=False to get exit code
        # Print the output for debugging purposes.  Remove in production.
        logging.debug(f"Command output: {result.stdout}")
        logging.debug(f"Command error: {result.stderr}")

        logging.info(f"Username check for {username} completed with exit status: {result.returncode}")
        return result.returncode
    except FileNotFoundError:
        logging.error("'id' command not found.")
        print("Error: 'id' command not found.")
        return 1  # Indicate failure
    except Exception as e:
        logging.exception(f"An error occurred: {e}")
        print(f"An error occurred: {e}")
        return 1  # Indicate failure


if __name__ == "__main__":
    # Check if 'id' command is available
    if not shutil.which("id"):
        logging.error("'id' command not found.  Exiting.")
        print("Error: 'id' command not found.  Exiting.")
        sys.exit(1)

    if len(sys.argv) != 2:
        print("Usage: python script.py <username>")
        sys.exit(1)

    username = sys.argv[1]
    exit_status = get_user_id(username)
    print(f"Exit status: {exit_status}")
    sys.exit(exit_status)

