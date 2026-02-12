import subprocess
import sys
import shlex
import logging

# Configure logging (optional)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def is_valid_username(username):
    """
    Validates the username to only allow alphanumeric characters and underscores.

    Args:
        username: The username to validate.

    Returns:
        True if the username is valid, False otherwise.
    """
    for i, c in enumerate(username):
        if not (c.isalnum() or c == '_'):
            logging.error(f"Invalid username: Character '{c}' at position {i+1} is not allowed.")
            print(f"Error: Invalid username. Character '{c}' at position {i+1} is not allowed.")
            return False
    return True


def get_user_info(username):
    """
    Retrieves user information from /etc/passwd using a safe method.

    Args:
        username: The username to search for.

    Returns:
        A string containing the user information if found, otherwise None.
    """

    # Allowlist of allowable commands: Only allow 'grep' because it's the only
    # command needed to search /etc/passwd and is carefully controlled.
    allowed_commands = ['grep']

    if not is_valid_username(username):
        return None

    try:
        # Use shlex.quote to properly escape the username for the grep command.
        quoted_username = shlex.quote(username)
        #command = f"grep {quoted_username} /etc/passwd"
        #command_list = shlex.split(command)
        command_list = ['grep', quoted_username, '/etc/passwd'] # Simplified command list

        # Check if the base command is in the allowlist
        if command_list[0] not in allowed_commands:
            logging.error(f"Command not allowed: {command_list[0]}")
            print("Error: Command not allowed.")
            return None

        # Use subprocess.run with shell=False for safety.
        try:
            result = subprocess.run(command_list, capture_output=True, text=True, shell=False, check=True, timeout=5) # Added timeout

            if result.returncode == 0:
                return result.stdout.strip()
            elif result.returncode == 1: # grep returns 1 if no match is found
                logging.info(f"User '{username}' not found in /etc/passwd")
                print(f"User '{username}' not found.")
                return None
            else:
                logging.warning(f"grep returned non-zero exit code: {result.returncode}")
                print("An error occurred while searching for the user.") # More generic message for the user
                return None  # User not found or error occurred.


        except subprocess.TimeoutExpired:
            logging.error("Command timed out.")
            print("Error: Command timed out.")
            return None

    except subprocess.CalledProcessError as e:
        logging.error(f"Error executing command: {e}")
        print("An error occurred while searching for the user.") # More generic message for the user
        return None
    except Exception as e:
        logging.exception(f"An unexpected error occurred: {e}") # Log the full exception traceback
        print("An unexpected error occurred.") # More generic message for the user
        return None


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python script.py <username>")
        sys.exit(1)

    username = sys.argv[1]
    user_info = get_user_info(username)

    if user_info:
        print(user_info)
    else:
        # The get_user_info function already prints "User not found"
        pass

