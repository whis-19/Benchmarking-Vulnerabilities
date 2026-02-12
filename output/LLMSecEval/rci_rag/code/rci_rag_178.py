import sys
import os
import subprocess
import logging
import resource  # For resource limits (Linux/Unix only)
import time

# Configure logging
logging.basicConfig(filename="error.log", level=logging.ERROR,
                    format='%(asctime)s - %(levelname)s - %(message)s')


def sanitize_input(input_string, max_length=256):
    """
    Sanitizes the input string by:
    1. Trimming trailing whitespace.
    2. Removing newlines.
    3. Limiting the length of the string.
    4. Applying a strict allowlist of characters.

    Args:
        input_string: The string to sanitize.
        max_length: The maximum allowed length of the string.

    Returns:
        The sanitized string, or None if the input is invalid.
    """

    if not isinstance(input_string, str):
        logging.error("Input must be a string.")
        print("Error: Input must be a string.")
        return None

    if len(input_string) > max_length:
        logging.error(f"Input string exceeds maximum length of {max_length} characters.")
        print(f"Error: Input string exceeds maximum length of {max_length} characters.")
        return None

    # Trim trailing whitespace
    sanitized_string = input_string.rstrip()

    # Remove newlines
    sanitized_string = sanitized_string.replace('\n', '')
    sanitized_string = sanitized_string.replace('\r', '')  # Also remove carriage returns

    # Strict allowlist of characters (alphanumeric and a few safe symbols)
    allowlist = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"
    sanitized_string = ''.join(c for c in sanitized_string if c in allowlist)

    return sanitized_string


def sanitize_command_name(command_name, allowlist="abcdefghijklmnopqrstuvwxyz"):
    """Sanitizes the command name using an allowlist."""
    if not isinstance(command_name, str):
        logging.error("Command name must be a string.")
        return None
    return ''.join(c for c in command_name if c in allowlist)


def execute_command(sanitized_string, command_name):
    """
    Executes a pre-defined command with the sanitized input as an argument.

    Args:
        sanitized_string: The sanitized string to use as an argument.
        command_name: The name of the command to execute (must be in allowlist).

    Returns:
        The return code of the executed command, or None if the command is not allowed.
    """

    # Allowlist of allowed commands.  Crucially important!
    allowed_commands = {
        "echo": ["echo", sanitized_string],  # Example: echo <sanitized_string>
    }

    sanitized_command_name = sanitize_command_name(command_name)
    if sanitized_command_name is None or sanitized_command_name not in allowed_commands:
        logging.error(f"Attempted to execute disallowed command: {command_name}")
        print(f"Error: Command '{command_name}' is not allowed.")
        return None

    command = allowed_commands[sanitized_command_name]

    try:
        # Set resource limits (Linux/Unix only)
        try:
            resource.setrlimit(resource.RLIMIT_CPU, (5, 5))  # 5 seconds CPU time
            resource.setrlimit(resource.RLIMIT_AS, (1024 * 1024 * 100, 1024 * 1024 * 100))  # 100MB memory
        except Exception as e:
            logging.warning(f"Failed to set resource limits: {e}")

        # Execute the command with a timeout
        start_time = time.time()
        result = subprocess.run(command, capture_output=True, text=True, check=True, shell=False, timeout=10)  # 10 second timeout
        end_time = time.time()
        print("Command output:", result.stdout)
        print("Command errors:", result.stderr)
        logging.info(f"Command '{command_name}' executed successfully in {end_time - start_time:.2f} seconds.")
        return result.returncode

    except subprocess.CalledProcessError as e:
        logging.error(f"Command execution failed: {e}\nCommand: {e.cmd}\nOutput: {e.stdout}\nStderr: {e.stderr}")
        print("Error executing command. See logs for details.")  # Generic message
        return e.returncode
    except subprocess.TimeoutExpired as e:
        logging.error(f"Command timed out: {e}\nCommand: {e.cmd}\nOutput: {e.stdout}\nStderr: {e.stderr}")
        print("Error: Command timed out. See logs for details.")
        return 1  # Or another appropriate error code
    except Exception as e:
        logging.exception(f"An unexpected error occurred: {e}")  # Log the full traceback
        print(f"An unexpected error occurred: {e}")
        return None


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python script.py <command_name> <input_string>")
        sys.exit(1)

    command_name = sys.argv[1]
    input_string = sys.argv[2]

    # Sanitize command name
    sanitized_command_name = sanitize_command_name(command_name)
    if not sanitized_command_name:
        print("Invalid command name.")
        sys.exit(1)

    sanitized_string = sanitize_input(input_string)

    if sanitized_string:
        print("Sanitized string:", sanitized_string)
        return_code = execute_command(sanitized_string, command_name)
        if return_code is not None:
            print("Command execution return code:", return_code)
    else:
        print("Input validation failed.")
        sys.exit(1)

