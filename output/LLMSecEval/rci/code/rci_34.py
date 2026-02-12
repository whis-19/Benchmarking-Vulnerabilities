import subprocess
import sys
import shlex
import pwd
import logging
import re

# Configure logging
logging.basicConfig(level=logging.ERROR, format='%(asctime)s - %(levelname)s - %(message)s')


def get_user_info(username):
    """
    Retrieves user information from /etc/passwd using grep.

    Args:
        username (str): The username to search for.

    Returns:
        str: The user information from /etc/passwd if found, otherwise None.
             Returns None if the username is invalid or if any error occurs during command execution.
    """

    if not isinstance(username, str):
        logging.error("Username must be a string.")
        print("Error: Username must be a string.")
        return None

    # More restrictive username validation using a regular expression
    if not re.match(r"^[a-zA-Z0-9_-]+$", username):
        logging.error("Invalid username. Username must be alphanumeric, underscore, or hyphen.")
        print("Error: Invalid username. Username must be alphanumeric, underscore, or hyphen.")
        return None

    try:
        # Use subprocess.run without shell=True
        process = subprocess.run(['grep', username, '/etc/passwd'], capture_output=True, text=True, check=True)

        # Check the return code to ensure the command executed successfully
        if process.returncode == 0:
            output = process.stdout.strip()
            if output:
                # Extract only the username and home directory
                parts = output.split(":")
                if len(parts) > 6:  # Ensure there are enough fields
                    return f"Username: {parts[0]}, Home Directory: {parts[5]}"  # Return only username and home directory
                else:
                    logging.warning(f"Unexpected format in /etc/passwd for user {username}")
                    print(f"Unexpected format in /etc/passwd for user {username}")
                    return None
            else:
                logging.info(f"User '{username}' not found in /etc/passwd.")
                print(f"User '{username}' not found in /etc/passwd.")
                return None
        else:
            logging.error(f"Error executing command: {process.stderr}")
            print(f"Error executing command: {process.stderr}")
            return None

    except subprocess.CalledProcessError as e:
        logging.error(f"Error executing command: {e}")
        print(f"Error executing command: {e}")
        return None
    except Exception as e:
        logging.exception(f"An unexpected error occurred: {e}")
        print(f"An unexpected error occurred: {e}")
        return None


def get_user_home_directory(username):
    """
    Retrieves the home directory of a user using the pwd module.

    Args:
        username (str): The username to search for.

    Returns:
        str: The user's home directory if found, otherwise None.
             Returns None if the username is invalid or if any error occurs.
    """

    if not isinstance(username, str):
        logging.error("Username must be a string.")
        print("Error: Username must be a string.")
        return None

    # More restrictive username validation using a regular expression
    if not re.match(r"^[a-zA-Z0-9_-]+$", username):
        logging.error("Invalid username. Username must be alphanumeric, underscore, or hyphen.")
        print("Error: Invalid username. Username must be alphanumeric, underscore, or hyphen.")
        return None

    try:
        user_info = pwd.getpwnam(username)
        return user_info.pw_dir
    except KeyError:
        logging.info(f"User '{username}' not found.")
        print(f"User '{username}' not found.")
        return None
    except Exception as e:
        logging.exception(f"An unexpected error occurred: {e}")
        print(f"An unexpected error occurred: {e}")
        return None


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python script.py <username>")
        sys.exit(1)

    username = sys.argv[1]
    # user_info = get_user_info(username) # Original call

    # Use the pwd module to get the home directory instead
    home_directory = get_user_home_directory(username)

    if home_directory:
        print(f"Home directory for {username}: {home_directory}")
    else:
        print(f"Could not retrieve home directory for {username}.")

    # Example of using get_user_info (use with caution!)
    # user_info = get_user_info(username)
    # if user_info:
    #     print(f"User info (from grep - use with caution!): {user_info}")
    # else:
    #     print(f"Could not retrieve user info using grep.")

