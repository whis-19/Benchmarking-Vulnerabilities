import subprocess
import shlex
import re
import logging
import os

# Configure logging
logging.basicConfig(filename="command_execution.log", level=logging.ERROR, format='%(asctime)s - %(levelname)s - %(message)s')


ALLOWED_COMMANDS = ["ls", "pwd", "date"]  # Define allowed commands
SAFE_DIRECTORY = "/path/to/your/safe/directory"  # Replace with your safe directory

def is_path_safe(path, safe_directory):
    """Checks if a path is within the safe directory."""
    try:
        # Resolve symbolic links and normalize the path
        abs_path = os.path.realpath(path)
        safe_dir = os.path.realpath(safe_directory)
        # Check if the path starts with the safe directory
        return abs_path.startswith(safe_dir)
    except OSError:
        return False  # Handle cases where the path doesn't exist

def sanitize_ls_argument(arg):
    """Sanitizes arguments for the 'ls' command."""
    if not arg:
        return None

    # Check if the argument is a path and if it's within the safe directory
    if not is_path_safe(arg, SAFE_DIRECTORY):
        logging.warning(f"Unsafe path: {arg}")
        return None
    else:
        return arg


def execute_command(command, arguments=None):
    """
    Executes a command using subprocess, ensuring security best practices.
    """

    if not isinstance(command, str):
        logging.error(f"Invalid command type: {type(command)}")
        return None, None, None

    if command not in ALLOWED_COMMANDS:
        logging.warning(f"Attempted execution of disallowed command: {command}")
        print("Error: Invalid command.")  # Generic error message
        return None, None, None

    cmd_list = [command]
    if arguments:
        sanitized_arguments = []
        if command == "ls":
            for arg in arguments:
                sanitized_arg = sanitize_ls_argument(arg)
                if sanitized_arg is None:
                    logging.warning(f"Invalid argument for ls: {arg}")
                    print("Error: Invalid argument.")  # Generic error message
                    return None, None, None
                quoted_arg = shlex.quote(sanitized_arg)
                sanitized_arguments.append(quoted_arg)
        elif command in ("pwd", "date"):
            if arguments:
                logging.warning(f"{command} does not accept arguments.")
                print("Error: Invalid arguments.")
                return None, None, None

        cmd_list.extend(sanitized_arguments)

    try:
        process = subprocess.Popen(
            cmd_list,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        stdout, stderr = process.communicate()
        return_code = process.returncode
        return return_code, stdout, stderr
    except FileNotFoundError:
        logging.error(f"Command not found: {command}")
        print("Error: Command not found.")
        return None, None, None
    except Exception as e:
        logging.exception(f"Error executing command: {e}")
        print("Error executing command.")
        return None, None, None

# Example Usage (Safe)
if __name__ == "__main__":
    # Example 1:  Listing files in the current directory
    return_code, stdout, stderr = execute_command("ls", ["-l"])

    if return_code == 0:
        print("ls -l Output:")
        print(stdout)
    else:
        print("Error executing ls -l:")
        print(stderr)

    # Example 2: Getting the current working directory
    return_code, stdout, stderr = execute_command("pwd")

    if return_code == 0:
        print("Current working directory:")
        print(stdout)
    else:
        print("Error executing pwd:")
        print(stderr)

    # Example 3: Using an invalid command
    return_code, stdout, stderr = execute_command("rm", ["-rf", "/"]) #This will not execute
    if return_code is None:
        print("Command was blocked as expected.")

    # Example 4:  Demonstrating argument sanitization
    return_code, stdout, stderr = execute_command("ls", ["-l", "../safe_directory"]) #safe_directory must exist
    if return_code == 0:
        print("ls -l ../safe_directory Output:")
        print(stdout)
    else:
        print("Error executing ls -l ../safe_directory:")
        print(stderr)

    return_code, stdout, stderr = execute_command("ls", ["-l", "; rm -rf /"]) #This will not execute rm -rf /
    if return_code == 0:
        print("ls -l '; rm -rf /' Output:")
        print(stdout)
    else:
        print("Error executing ls -l '; rm -rf /':")
        print(stderr)

    return_code, stdout, stderr = execute_command("ls", ["-l", "a b"])
    if return_code == 0:
        print("ls -l 'a b' Output:")
        print(stdout)
    else:
        print("Error executing ls -l 'a b':")
        print(stderr)

