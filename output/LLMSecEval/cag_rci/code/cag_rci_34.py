import subprocess
import sys
import os
import html
import re
import pwd  # Import the pwd module
import logging  # Import the logging module
import shlex

# --- Security Configuration ---
ALLOWED_COMMANDS = ["grep"]  # Allowlist of allowed commands
#PASSWD_FILE = os.environ.get("PASSWD_FILE", "/etc/passwd")  # Define the passwd file path, allow override

# --- Input Validation and Sanitization ---
def sanitize_username(username):
    """
    Sanitizes the username to prevent command injection.
    Removes potentially harmful characters.
    """
    # Remove characters that could be used for command injection
    sanitized_username = re.sub(r"[^a-zA-Z0-9_-]", "", username)
    return sanitized_username

# --- Command Execution ---
def execute_command(command, args):
    """
    Executes a command using subprocess.  Avoids shell=True.
    Validates the command against an allowlist.
    """
    if command not in ALLOWED_COMMANDS:
        logging.warning(f"Attempted execution of disallowed command: {command}")
        print(f"Error: Command '{command}' is not allowed.")
        return None

    try:
        # Escape special characters in the username for grep
        escaped_args = [shlex.quote(arg) for arg in args]  # Use shlex.quote
        result = subprocess.run([command] + escaped_args, capture_output=True, text=True, check=True)
        logging.info(f"Successfully executed command: {command} with args: {args}") # Log successful execution
        return result.stdout
    except subprocess.CalledProcessError as e:
        logging.error(f"Error executing command: {e}. Stderr: {e.stderr}")  # Log stderr
        print("Error executing command. See logs for details.")  # Generic error message
        return None
    except FileNotFoundError:
        logging.error(f"Command '{command}' not found.")
        print(f"Error: Command '{command}' not found.")
        return None
    except Exception as e:
        logging.exception("Unexpected error during command execution")  # Log the error
        print("Error: An unexpected error occurred. See logs for details.")
        return None

# --- Main Program ---
def get_user_info(username):
    """
    Retrieves user information using pwd module.
    """
    sanitized_username = sanitize_username(username)

    try:
        user_info = pwd.getpwnam(sanitized_username)
        return html.escape(str(user_info))  # Escape the string representation of the user info
    except KeyError:
        return html.escape(f"User '{username}' not found.") # Escape the entire message
    except PermissionError:
        logging.error("Insufficient permissions to access user information.")
        print("Error: Insufficient permissions to access user information.")
        return None
    except Exception as e:
        logging.exception(f"Error retrieving user info: {e}") # Log the exception
        print("Error retrieving user info. See logs for details.")
        return None

if __name__ == "__main__":
    # Configure logging (optional)
    logging.basicConfig(level=logging.ERROR, format='%(asctime)s - %(levelname)s - %(message)s')

    if len(sys.argv) != 2:
        print("Usage: python script.py <username>")
        sys.exit(1)

    username = sys.argv[1]
    user_info = get_user_info(username)

    if user_info:
        print(user_info)

