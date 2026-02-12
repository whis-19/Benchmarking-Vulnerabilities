import subprocess
import sys
import os
import re
import logging

# Configure logging (optional, but highly recommended)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

ALLOWED_USERNAME_CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_."
MAX_USERNAME_LENGTH = 32

def execute_command(command, args):
    """
    Executes a command with the given arguments, enforcing a command whitelist.
    """
    allowed_commands = ["id"]  # Define allowed commands here

    if command not in allowed_commands:
        logging.error(f"Command '{command}' is not allowed.")
        return -1, "", ""  # Return error code and empty output

    try:
        # Use the full path to the executable
        result = subprocess.run([f"/usr/bin/{command}"] + args, capture_output=True, text=True, check=False)
        return result.returncode, result.stdout, result.stderr
    except FileNotFoundError:
        logging.error(f"Command '{command}' not found.")
        return -1, "", ""
    except Exception as e:
        logging.exception(f"Error executing '{command}': {e}")
        return -1, "", ""


def sanitize_output(output):
    """
    Sanitizes command output to remove potentially sensitive information.
    """
    # Limit length
    sanitized_output = output[:100]
    # Remove newlines
    sanitized_output = sanitized_output.replace("\n", " ")
    # Example: Redact potential IP addresses (replace with "REDACTED")
    sanitized_output = re.sub(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', 'REDACTED', sanitized_output)
    return sanitized_output


def get_user_id_status(username):
    """
    Runs the 'id' command for a given username and returns the exit status.

    Args:
        username (str): The username to check.

    Returns:
        int: The exit status of the 'id' command.  0 indicates success,
             non-zero indicates failure.  Returns -1 if the username is invalid.
    """

    # Input validation and sanitization
    if not isinstance(username, str):
        logging.error("Username must be a string.")
        return -1

    if not re.match(f"^[{re.escape(ALLOWED_USERNAME_CHARS)}]{{1,{MAX_USERNAME_LENGTH}}}$", username):
        logging.warning(f"Invalid username format: {username}") # Log the invalid username
        print("Error: Invalid input.") # Generic error message to the user
        return -1

    try:
        return_code, stdout, stderr = execute_command("id", [username])

        if return_code == 0:
            logging.info(f"'id {username}' command executed successfully.")
        else:
            sanitized_stdout = sanitize_output(stdout)
            sanitized_stderr = sanitize_output(stderr)
            logging.warning(f"'id {username}' command failed with exit code {return_code}.  Stdout: {sanitized_stdout}, Stderr: {sanitized_stderr}") # Log details

            if return_code == 1:  # Example: User not found
                print("Error: User not found.") # Slightly more specific error
            else:
                print("Error: Internal error. Please contact the administrator.") # Generic error message

        return return_code
    except FileNotFoundError:
        logging.error("The 'id' command was not found.")
        print("Error: Internal error. Please contact the administrator.") # Generic error message
        return -1
    except Exception as e:
        logging.exception(f"An unexpected error occurred: {e}") # Log the full exception
        print("Error: Internal error. Please contact the administrator.") # Generic error message
        return -1


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python script.py <username>")
        sys.exit(1)

    username = sys.argv[1]
    exit_status = get_user_id_status(username)

    if exit_status != -1:
        print(f"User existence check status: {exit_status}") # Avoid printing the username
    else:
        print("Failed to get user existence status.")
        sys.exit(1)

