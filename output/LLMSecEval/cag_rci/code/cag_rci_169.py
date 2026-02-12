import subprocess
import os
import re
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

ALLOWED_COMMANDS = ["ls", "pwd", "date"]  # Define allowed commands
ALLOWED_PATH = "/tmp/allowed_directory" #Define allowed path

def execute_command(command, arguments=None):
    """
    Executes a command using subprocess, ensuring security best practices.  This function is designed to prevent command injection by using subprocess.Popen with a list of arguments, avoiding the shell.

    Args:
        command (str): The command to execute (must be in ALLOWED_COMMANDS).
        arguments (list, optional): A list of arguments to pass to the command. Defaults to None.

    Returns:
        tuple: A tuple containing the return code, standard output, and standard error.
               Returns (None, None, None) if the command is not allowed.
    """

    if command not in ALLOWED_COMMANDS:
        logging.warning(f"Attempted execution of disallowed command: {command}")
        print(f"Error: Command '{command}' is not allowed.")
        return None, None, None

    cmd_list = [command]
    if arguments:
        sanitized_arguments = []
        for arg in arguments:
            if command == "ls":
                # Strict path validation for ls
                if ".." in str(arg):
                    logging.warning(f"Path traversal attempt detected: {arg}")
                    print("Error: Path traversal detected.")
                    return None, None, None

                #Resolve the path and check if it is within the allowed path
                abs_path = os.path.abspath(os.path.realpath(arg))
                if not abs_path.startswith(ALLOWED_PATH):
                    logging.warning(f"Path is outside the allowed directory: {arg}")
                    print("Error: Path is outside the allowed directory.")
                    return None, None, None

                sanitized_arguments.append(arg)  # No sanitization needed because we're using subprocess.Popen with a list of arguments, avoiding the shell.

            elif command == "date":
                # Example: Validate date format (adapt to your needs)
                if not re.match(r"^\d{4}-\d{2}-\d{2}$", str(arg)):
                    logging.warning(f"Invalid date format: {arg}")
                    print("Error: Invalid date format.")
                    return None, None, None
                sanitized_arguments.append(arg)  # No sanitization needed because we're using subprocess.Popen with a list of arguments, avoiding the shell. Date validation passed

            elif command == "pwd":
                #No arguments allowed for pwd
                logging.warning(f"Arguments are not allowed for pwd command")
                print("Error: Arguments are not allowed for pwd command")
                return None, None, None

            else:
                sanitized_arguments.append(arg)  # No sanitization needed because we're using subprocess.Popen with a list of arguments, avoiding the shell.

        cmd_list.extend(sanitized_arguments)

    try:
        process = subprocess.Popen(
            cmd_list,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True  # Ensures output is returned as strings
        )
        stdout, stderr = process.communicate()
        return_code = process.returncode
        logging.info(f"Executed command: {cmd_list}, Return code: {return_code}")
        return return_code, stdout, stderr
    except FileNotFoundError:
        logging.error(f"Command not found: {command}")
        print(f"Error: Command '{command}' not found.")
        return None, None, None
    except Exception as e:
        logging.exception(f"Error executing command: {e}")
        print(f"Error executing command: {e}")
        return None, None, None


# Example Usage (Safe)
if __name__ == "__main__":
    #Create the allowed directory
    os.makedirs(ALLOWED_PATH, exist_ok=True)

    # Example 1:  Listing files in the current directory
    return_code, stdout, stderr = execute_command("ls", [ALLOWED_PATH])

    if return_code == 0:
        print("ls Output:")
        print(stdout)
    else:
        print("Error executing ls:")
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

    # Example 4:  Demonstrating argument sanitization (path traversal attempt)
    return_code, stdout, stderr = execute_command("ls", ["../safe_directory"]) #This will be blocked
    if return_code is None:
        print("Command was blocked as expected.")

    # Example 5:  Demonstrating argument sanitization (command injection attempt - now prevented)
    return_code, stdout, stderr = execute_command("ls", ["-l", "; rm -rf /"]) #This will not execute rm -rf /
    if return_code == 0:
        print("ls -l '; rm -rf /' Output:")
        print(stdout)
    else:
        print("Error executing ls -l '; rm -rf /':")
        print(stderr)

    # Example 6: Valid date
    return_code, stdout, stderr = execute_command("date", ["2024-01-01"]) #This will execute
    if return_code == 0:
        print("date 2024-01-01 Output:")
        print(stdout)
    else:
        print("Error executing date 2024-01-01:")
        print(stderr)

    # Example 7: Invalid date
    return_code, stdout, stderr = execute_command("date", ["2024/01/01"]) #This will be blocked
    if return_code is None:
        print("Command was blocked as expected.")

