import sys
import os
import subprocess
import logging
import shlex
import unicodedata
import resource  # For resource limits

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

ALLOWED_COMMANDS = ["cat", "head", "tail"]  # Whitelist of allowed commands
MAX_FILENAME_LENGTH = 255

def is_valid_filename(filename):
    """
    Validates that the filename contains only allowed characters and prevents path traversal.
    """
    # Normalize Unicode filename
    filename = unicodedata.normalize('NFKC', filename)

    allowed_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-"
    if not all(c in allowed_chars for c in filename):
        logging.warning(f"Invalid characters in filename: {filename}")
        return False

    if ".." in filename:
        logging.warning(f"Path traversal attempt detected: {filename}")
        return False

    if len(filename) > MAX_FILENAME_LENGTH:
        logging.warning(f"Filename too long: {filename}")
        return False

    if not filename:
        logging.warning("Filename is empty.")
        return False

    # Null byte check
    if '\0' in filename:
        logging.warning("Null byte detected in filename.")
        return False

    logging.info(f"Filename validated: {filename}")
    return True

def execute_command(command, filename):
    """
    Executes a command with the given filename, after validation.
    """
    if command not in ALLOWED_COMMANDS:
        logging.error(f"Command not allowed: {command}")
        print("Error: Command not allowed.")
        return

    if not is_valid_filename(filename):
        print("Error: Invalid filename.")
        return

    try:
        # Resolve symlinks and get absolute path
        real_path = os.path.realpath(os.path.abspath(filename))

        # Open the file *before* running the command (file descriptor approach)
        try:
            with open(real_path, 'r') as file_obj:
                # Set resource limits (example - memory limit)
                resource.setrlimit(resource.RLIMIT_AS, (1024 * 1024 * 100, resource.RLIM_INFINITY)) # 100MB

                result = subprocess.run([command, file_obj.name], capture_output=True, text=True, timeout=5) # Pass file_obj.name instead of real_path
        except OSError as e:
            logging.error(f"Error opening file: {e}")
            print("Error: Could not open file.")
            return


        if result.returncode == 0:
            print(result.stdout)
        else:
            logging.error(f"Error executing command: {result.stderr}")
            print("Error executing command.")  # Generic error message for the user
    except FileNotFoundError:
        logging.error(f"Command not found: {command}")
        print("Error: Command not found.")
    except subprocess.TimeoutExpired:
        logging.error(f"Command timed out: {command} {filename}")
        print("Error: Command timed out.")
    except Exception as e:
        logging.exception(f"An unexpected error occurred: {e}")
        print("An unexpected error occurred.") # Generic error message for the user


def main():
    """
    Main function to process the command line arguments.
    """
    if len(sys.argv) < 3:
        print("Error: Please provide a command and a filename argument.")
        sys.exit(1)

    command = sys.argv[1]
    filename = sys.argv[2]

    execute_command(command, filename)


if __name__ == "__main__":
    main()

