import subprocess
import shlex
import os
import logging
import re  # Import the regular expression module

# Configure logging (replace with your desired configuration)
logging.basicConfig(filename='command_execution.log', level=logging.ERROR)

ALLOWED_COMMANDS = ["ls", "pwd", "date"]  # Define allowed commands

def execute_command(command, arguments=None):
    """
    Executes a command using subprocess, with security measures.

    Args:
        command (str): The command to execute (must be in ALLOWED_COMMANDS).
        arguments (list, optional): A list of arguments to pass to the command. Defaults to None.

    Returns:
        tuple: A tuple containing the return code and the output (stdout and stderr combined) of the command.
               Returns (None, None) if the command is not allowed or if validation fails.
    """

    if command not in ALLOWED_COMMANDS:
        logging.warning(f"Attempted execution of disallowed command: {command}")
        print(f"Error: Command '{command}' is not allowed.")
        return None, None

    if arguments:
        # Validate and sanitize arguments (example: only allow alphanumeric characters and hyphens)
        if command == "ls":
            for arg in arguments:
                if not isinstance(arg, str):
                    logging.warning(f"Invalid argument type for 'ls': {arg}")
                    print(f"Error: Argument '{arg}' is not a string.")
                    return None, None
                # Allow -l, -a, -t, and paths that start with /tmp/ followed by alphanumeric characters, underscores, hyphens, and dots.
                if not re.match(r"^-?[lat]$|^/tmp/[a-zA-Z0-9_\-\.]*$", arg):
                    logging.warning(f"Invalid argument for 'ls': {arg}")
                    print(f"Error: Invalid argument '{arg}' for command 'ls'.")
                    return None, None
        elif command == "date":
            # Example: Disallow format strings for date
            for arg in arguments:
                if "%" in arg:
                    logging.warning(f"Format strings are not allowed for 'date': {arg}")
                    print("Error: Format strings are not allowed for 'date'.")
                    return None, None
        elif command == "pwd":
            if arguments:
                logging.warning(f"pwd does not accept arguments: {arguments}")
                print("Error: pwd does not accept arguments")
                return None, None
        else:
            logging.error(f"No validation rules defined for command: {command}")
            print("Error: No validation rules defined for this command.")
            # Raise an exception to prevent execution
            raise ValueError(f"No validation rules defined for command: {command}")
            return None, None

    try:
        cmd = [command]
        if arguments:
            cmd.extend(arguments)

        # Use subprocess.run with explicit arguments and capture output
        result = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=10, env={})  # check=False to handle non-zero exit codes, timeout, clean env

        return result.returncode, result.stdout + result.stderr  # Combine stdout and stderr

    except FileNotFoundError:
        logging.error(f"Command not found: {command}")
        print(f"Error: Command '{command}' not found.")
        return None, None
    except subprocess.TimeoutExpired:
        logging.error(f"Command timed out: {command} with arguments: {arguments}")
        print("Error: Command timed out.")
        return None, None
    except Exception as e:
        logging.exception(f"Error executing command: {command} with arguments: {arguments}")
        print(f"An unexpected error occurred.")
        return None, None


# Example usage:
if __name__ == "__main__":
    # Allowed command with arguments
    return_code, output = execute_command("ls", ["-l", "/tmp/test"])
    if return_code is not None:
        print(f"Return Code: {return_code}")
        print(f"Output:\n{output}")

    # Allowed command without arguments
    return_code, output = execute_command("pwd")
    if return_code is not None:
        print(f"Return Code: {return_code}")
        print(f"Output:\n{output}")

    # Disallowed command
    return_code, output = execute_command("rm", ["-rf", "/tmp/*"])  # Intentionally disallowed
    if return_code is not None:
        print(f"Return Code: {return_code}")
        print(f"Output:\n{output}") # This will not execute because the command is disallowed.

    # Command with invalid arguments
    return_code, output = execute_command("ls", ["-l", "; rm -rf /"]) # Intentionally invalid
    if return_code is not None:
        print(f"Return Code: {return_code}")
        print(f"Output:\n{output}") # This will not execute because the arguments are invalid.

    # Command with non-string arguments
    return_code, output = execute_command("ls", ["-l", 123])
    if return_code is not None:
        print(f"Return Code: {return_code}")
        print(f"Output:\n{output}")

    # Command with no validation rules
    try:
        return_code, output = execute_command("new_command", ["arg1", "arg2"]) # Intentionally invalid
    except ValueError as e:
        print(f"Caught expected error: {e}")

