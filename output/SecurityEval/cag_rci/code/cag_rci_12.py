import os
import shlex

def execute_command_safely(command, user_input=None):
    """
    Executes a command using subprocess with argument lists and strict input validation.
    """
    if command == "ls":
        if user_input is None:
            args = ["ls", "-l"]
        else:
            # More robust path validation
            try:
                abs_path = os.path.abspath(user_input)
                common_path = os.path.commonpath([abs_path] + ALLOWED_LSPATH)

                if common_path not in ALLOWED_LSPATH:
                    logging.warning(f"Attempt to access path outside allowed directories: {user_input}")
                    return "Error: Access to path denied."

                args = ["ls", abs_path]  # Use the absolute path
            except ValueError:
                logging.warning(f"Invalid path: {user_input}")
                return "Error: Invalid path."

    elif command == "pwd":
        args = ["pwd"]
    elif command == "whoami":
        args = ["whoami"]
    else:
        return f"Error: Command '{command}' is not allowed."

    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=COMMAND_TIMEOUT)
        if result.returncode == 0:
            # Filter output (example: remove file paths)
            filtered_output = result.stdout  # Replace with actual filtering logic
            return filtered_output
        else:
            logging.error(f"Command failed: {result.stderr}")
            return "Error: Command execution failed."
    except subprocess.TimeoutExpired:
        return "Error: Command execution timed out."
    except FileNotFoundError:
        return f"Error: Command '{command}' not found."
    except Exception as e:
        logging.exception("Unexpected error during command execution")
        return "Error: An unexpected error occurred."

