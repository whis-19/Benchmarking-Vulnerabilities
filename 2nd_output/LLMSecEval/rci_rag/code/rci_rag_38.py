import subprocess
import shlex
import os
import re
import pathlib
import logging

# Configure logging (replace with your desired configuration)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def execute_ls(directory):
    """
    Executes the 'ls' command securely within a restricted environment.

    Args:
        directory: The directory to list.  This input is carefully validated.

    Returns:
        A string containing the output of the 'ls' command, or None if an error occurred.
    """

    # 1. Allowlist of allowable commands:  Only 'ls' is permitted.
    allowed_commands = ["ls"]

    # 2. Input Validation and Sanitization:  Strict allowlist for directory characters.
    allowed_directory_chars = "a-zA-Z0-9_/-"

    try:
        # Canonicalize the path
        try:
            directory = str(pathlib.Path(directory).resolve(strict=False)) # Resolve symlinks if they exist, but don't error if the path doesn't exist
        except OSError as e:
            logging.error(f"Error resolving path: {e}")
            return None


        if not re.match(f"^[{allowed_directory_chars}]+$", directory):
            logging.error("Invalid directory name.  Only alphanumeric characters, underscores, hyphens, and forward slashes are allowed.")
            return None

        # Check filesystem permissions
        try:
            if not os.access(directory, os.R_OK):
                logging.error(f"Insufficient permissions to access directory: {directory}")
                return None
        except OSError as e:
            logging.error(f"Error checking permissions: {e}")
            return None


        # 3. Static Command Creation: The base command is static.
        command = ["ls", directory]

        # 4. Use subprocess.run with shlex.quote for safe argument passing.
        try:
            # Construct the command string for logging purposes (optional, but helpful for auditing)
            command_str = " ".join(shlex.quote(arg) for arg in command)
            logging.info(f"Executing command: {command_str}")  # Log the command

            result = subprocess.run(command, capture_output=True, text=True, check=True, timeout=10)

            return result.stdout

        except subprocess.CalledProcessError as e:
            logging.error(f"Error executing command: {e}")
            logging.error(f"Stderr: {e.stderr}")
            return None
        except subprocess.TimeoutExpired as e:
            logging.error(f"Command timed out: {e}")
            return None
        except Exception as e:
            logging.exception(f"An unexpected error occurred: {e}") # Use logging.exception to include traceback
            return None

    except Exception as e:
        logging.exception(f"An error occurred during path processing: {e}") # Use logging.exception to include traceback
        return None


# Example usage:
if __name__ == "__main__":
    user_directory = input("Enter a directory to list (e.g., /tmp or a subdirectory): ")

    output = execute_ls(user_directory)

    if output:
        print("Output:")
        print(output)
    else:
        print("Failed to execute ls command.")

