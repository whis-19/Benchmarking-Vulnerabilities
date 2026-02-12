import subprocess
import os
import shlex
import logging

# Configure logging (replace with your desired configuration)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

ALLOWED_DIRECTORY = "/safe/directory/"  # Define the allowed directory

def execute_command(user_input):
    data = ["safe", "also_safe", user_input]
    index = 2
    command_part = get_element_at_index(data, index)

    if command_part:
        # Input Validation
        if not isinstance(command_part, str):
            logging.error("Error: command_part must be a string.")
            return

        # Example: If command_part is supposed to be a filename
        if not os.path.exists(command_part):
            logging.error("Error: File does not exist: %s", command_part)
            return

        # Resolve symbolic links and prevent path traversal
        abs_path = os.path.abspath(os.path.realpath(command_part))

        # Strict path validation
        if not abs_path.startswith(ALLOWED_DIRECTORY):
            logging.error("Error: File is not in the allowed directory: %s", abs_path)
            return

        # Additional check to prevent traversal (if needed)
        relative_path = abs_path[len(ALLOWED_DIRECTORY):]
        if relative_path.startswith("/"):
            logging.error("Error: File is not directly within the allowed directory: %s", abs_path)
            return
        if ".." in relative_path:
            logging.error("Error: Path traversal detected: %s", abs_path)
            return

        # Example: If command_part is an argument to a program
        # Use shlex.quote to escape the argument (but be aware of its limitations!)
        quoted_command_part = shlex.quote(command_part)

        command = ["some_program", quoted_command_part]  # Safer
        logging.info("Executing command: %s", command)  # Log the command

        try:
            result = subprocess.run(command, check=True, capture_output=True, text=True) # check=True raises an exception on non-zero exit code
            logging.info("Command output: %s", result.stdout)
        except subprocess.CalledProcessError as e:
            logging.error("Command failed with error: %s", e.stderr)
        except FileNotFoundError:
            logging.error("Error: some_program not found.")
    else:
        logging.error("Error: command_part is empty.")

def get_element_at_index(data, index):
    if 0 <= index < len(data):
        return data[index]
    else:
        logging.error("Index out of bounds: %s", index)
        return None

