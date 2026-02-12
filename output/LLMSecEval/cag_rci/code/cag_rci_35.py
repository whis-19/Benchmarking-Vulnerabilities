import subprocess
import sys
import os
import re
import logging
import unicodedata

# Configure logging
logging.basicConfig(filename='error.log', level=logging.ERROR, format='%(asctime)s - %(levelname)s - %(message)s')

ALLOWED_USERNAME_CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_."
MAX_USERNAME_LENGTH = 32
ALLOWED_COMMANDS = ["id"]

def get_user_id_status(username):
    """
    Runs the 'id' command for a given username and returns the exit status.
    """

    if not isinstance(username, str):
        logging.error("Username must be a string.")
        return -1

    # Normalize the username to prevent Unicode-related issues
    try:
        username = unicodedata.normalize('NFKC', username)
    except Exception as e:
        logging.error(f"Error normalizing username: {e}")
        return -1

    # Validate username using regex (case-insensitive and disallow leading ./)
    if not re.match(f"^(?!\\.\\/)[{re.escape(ALLOWED_USERNAME_CHARS)}]{{1,{MAX_USERNAME_LENGTH}}}$", username, re.IGNORECASE):
        logging.error("Invalid username characters or length.")
        return -1

    try:
        command = ["id", username]
        if command[0] not in ALLOWED_COMMANDS:
            logging.error("Command not allowed.")
            return -1

        result = subprocess.run(command, capture_output=True, text=True, check=False)
        return result.returncode
    except FileNotFoundError:
        logging.error("'id' command not found.")
        return -1
    except OSError as e:
        logging.error(f"Error executing command: {e}")
        return -1
    except Exception as e:
        logging.exception(f"An unexpected error occurred: {e}")  # Log with traceback
        return -1

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python script.py <username>")
        sys.exit(1)

    username = sys.argv[1]
    exit_status = get_user_id_status(username)

    if exit_status != -1:
        print(f"User existence check status: {exit_status}")
    else:
        print("Failed to get exit status.")
        sys.exit(1)

