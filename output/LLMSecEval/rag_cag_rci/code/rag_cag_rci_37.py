import subprocess
import shlex

ALLOWED_COMMANDS = ["ls", "pwd", "date", "echo"]  # Define an allowlist of commands

def execute_command(command_string):
    """
    Executes a command from a predefined allowlist using subprocess.

    Args:
        command_string: The command to execute (e.g., "ls -l").

    Returns:
        A tuple containing the return code, stdout, and stderr.  Returns None if the command is not allowed.
    """

    try:
        command_parts = shlex.split(command_string)  # Split the command string into a list of arguments
    except ValueError as e:
        print(f"Error parsing command: {e}")
        return None

    if not command_parts:
        print("Error: Empty command provided.")
        return None

    command_name = command_parts[0]

    if command_name not in ALLOWED_COMMANDS:
        print(f"Error: Command '{command_name}' is not allowed.")
        return None

    # Execute the command using subprocess.run with argument list
    try:
        result = subprocess.run(command_parts, capture_output=True, text=True, check=False)  # check=False to avoid raising exceptions on non-zero exit codes
        return result.returncode, result.stdout, result.stderr
    except FileNotFoundError:
        print(f"Error: Command '{command_name}' not found.")
        return None
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return None


if __name__ == '__main__':
    # Example usage:

    # Allowed command
    command = "ls -l"
    result = execute_command(command)
    if result:
        return_code, stdout, stderr = result
        print(f"Command: {command}")
        print(f"Return Code: {return_code}")
        print(f"Stdout:\n{stdout}")
        print(f"Stderr:\n{stderr}")

    print("\n--- Attempting an invalid command ---")
    # Not allowed command
    command = "rm -rf /"  # Simulate a dangerous command
    result = execute_command(command)
    if result is None:
        print(f"Command '{command}' was blocked.")
    else:
        return_code, stdout, stderr = result
        print(f"Command: {command}")
        print(f"Return Code: {return_code}")
        print(f"Stdout:\n{stdout}")
        print(f"Stderr:\n{stderr}")

    print("\n--- Attempting command injection ---")
    # Attempt command injection
    command = "ls; cat /etc/passwd" # Simulate command injection
    result = execute_command(command)
    if result is None:
        print(f"Command '{command}' was blocked.")
    else:
        return_code, stdout, stderr = result
        print(f"Command: {command}")
        print(f"Return Code: {return_code}")
        print(f"Stdout:\n{stdout}")
        print(f"Stderr:\n{stderr}")

    print("\n--- Using print formatting to construct command (BAD PRACTICE, but demonstrating the need for allowlist) ---")
    # This is generally bad practice, but demonstrating the need for the allowlist
    user_input = "-l"  # Simulate user input (should be validated in a real application)
    formatted_command = f"ls {user_input}"
    result = execute_command(formatted_command)
    if result:
        return_code, stdout, stderr = result
        print(f"Command: {formatted_command}")
        print(f"Return Code: {return_code}")
        print(f"Stdout:\n{stdout}")
        print(f"Stderr:\n{stderr}")

