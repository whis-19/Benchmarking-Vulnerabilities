import subprocess
import shlex
import os
import logging
import re  # For regular expression validation

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

ALLOWED_COMMANDS = {
    "ls": {
        "args": ["-l", "-a", "-la"],
        "path": "/safe/directory"  # Allowed path for 'ls'
    },
    "pwd": {
        "args": []
    },
    "date": {
        "args": ["+%Y-%m-%d"],
        "regex": [r"^\+\d{4}-\d{2}-\d{2}$"]  # Example regex for date format
    }
}

def is_path_safe(path, allowed_base_path):
    """Checks if a path is within the allowed base path."""
    try:
        abs_path = os.path.abspath(os.path.realpath(path))  # Normalize path
        common_path = os.path.commonpath([allowed_base_path, abs_path])
        return common_path == allowed_base_path
    except ValueError:
        return False  # Paths on different drives/mount points

def execute_command(command_string):
    """
    Executes a command line utility securely.

    Args:
        command_string: The command to execute (e.g., "ls -l /safe/directory").

    Returns:
        A tuple containing the return code, standard output, and standard error.
        Returns None if the command is not allowed or input validation fails.
    """

    try:
        command_list = shlex.split(command_string)

        if not command_list:
            logging.warning("Empty command provided.")
            print("Error: Invalid command.")  # Generic error message
            return None

        base_command = command_list[0]
        if base_command not in ALLOWED_COMMANDS:
            logging.warning(f"Command '{base_command}' is not allowed.")
            print("Error: Unauthorized operation.")  # Generic error message
            return None

        command_config = ALLOWED_COMMANDS[base_command]
        allowed_args = command_config.get("args", [])
        allowed_path = command_config.get("path")
        regex_patterns = command_config.get("regex", [])

        # Argument Validation
        if allowed_args:
            provided_args = set(command_list[1:])
            if not provided_args.issubset(set(allowed_args)):
                logging.warning(f"Invalid arguments for command '{base_command}'. Allowed: {allowed_args}, Provided: {provided_args}")
                print("Error: Invalid command arguments.")
                return None

        # Path Validation (if applicable)
        if allowed_path:
            if len(command_list) > 1:
                path_arg = command_list[1]
                if not is_path_safe(path_arg, allowed_path):
                    logging.warning(f"Path '{path_arg}' is not allowed. Allowed base path: {allowed_path}")
                    print("Error: Unauthorized path.")
                    return None

        # Regular Expression Validation (if applicable)
        if regex_patterns:
            for i, pattern in enumerate(regex_patterns):
                if len(command_list) > i + 1:  # Check if argument exists
                    arg_to_validate = command_list[i + 1]
                    if not re.match(pattern, arg_to_validate):
                        logging.warning(f"Argument '{arg_to_validate}' does not match regex pattern '{pattern}'.")
                        print("Error: Invalid argument format.")
                        return None


        result = subprocess.run(
            command_list,
            capture_output=True,
            text=True,
            check=False
        )

        if result.returncode != 0:
            logging.error(f"Command '{command_string}' failed with return code: {result.returncode}.  Stderr: {result.stderr}")
            print("Error: Command execution failed.")
            return None

        logging.info(f"Command '{command_string}' executed successfully. Return code: {result.returncode}")
        return result.returncode, result.stdout, result.stderr

    except ValueError as e:
        logging.error(f"Invalid command format: {e}", exc_info=True) # Log with exception chaining
        print("Error: Invalid command format.")
        return None
    except FileNotFoundError:
        logging.error(f"Command '{base_command}' not found.")
        print("Error: Command not found.")
        return None
    except Exception as e:
        logging.exception(f"An unexpected error occurred: {e}")  # Log the full exception
        print("An unexpected error occurred.")
        return None

