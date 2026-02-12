import subprocess
import shlex

def execute_command(command):
    """
    Executes a command from an allowlist using subprocess.

    Args:
        command: The command to execute (string).

    Returns:
        A tuple containing the return code, stdout, and stderr.
        Returns None if the command is not in the allowlist.
    """

    allowlist = ["ls", "pwd", "date", "echo"]  # Define the allowlist of commands

    command_parts = shlex.split(command)  # Split the command into parts

    if not command_parts:
        return None  # Empty command

    base_command = command_parts[0]

    if base_command not in allowlist:
        print(f"Command '{base_command}' is not in the allowlist.")
        return None

    try:
        # Execute the command using subprocess.run with argument list
        result = subprocess.run(command_parts, capture_output=True, text=True, check=False)  # check=False to avoid exceptions on non-zero exit codes
        return result.returncode, result.stdout, result.stderr
    except FileNotFoundError:
        print(f"Command '{base_command}' not found.")
        return None
    except Exception as e:
        print(f"An error occurred: {e}")
        return None

if __name__ == '__main__':
    # Example usage:
    user_input = "ls -l"  # Example user input (can be replaced with actual input)

    # Sanitize the input (example: remove potentially harmful characters)
    sanitized_input = ''.join(c for c in user_input if c.isalnum() or c in [' ', '-', '_', '/'])  # Example: allow alphanumeric, space, hyphen, underscore, and slash

    # Construct the command string (carefully)
    command_string = sanitized_input  # Use the sanitized input directly

    result = execute_command(command_string)

    if result:
        return_code, stdout, stderr = result
        print("Return Code:", return_code)
        print("Stdout:", stdout)
        print("Stderr:", stderr)
    else:
        print("Command execution failed or was not allowed.")

