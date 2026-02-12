import subprocess
import shlex

def execute_command(command, arguments=None):
    """
    Executes a command using subprocess, adhering to security best practices.

    Args:
        command (str): The command to execute (e.g., 'ls', 'grep').  Must be in the allowlist.
        arguments (list, optional): A list of arguments to pass to the command. Defaults to None.

    Returns:
        tuple: A tuple containing the return code, stdout, and stderr.
               Returns (None, None, None) if the command is not allowed.
    """

    # 1. Allowlist of allowed commands.  Crucial security measure.
    allowed_commands = ['ls', 'grep', 'cat', 'pwd', 'head', 'tail']  # Add more as needed, VERY CAREFULLY.

    if command not in allowed_commands:
        print(f"Error: Command '{command}' is not in the allowlist.")
        return None, None, None

    # 2. Input validation and sanitization (for arguments, if any).
    if arguments:
        sanitized_arguments = []
        for arg in arguments:
            # Implement more robust sanitization as needed.  This is a basic example.
            # This example only allows alphanumeric characters, underscores, hyphens, and dots.
            sanitized_arg = ''.join(c for c in arg if c.isalnum() or c in ['_', '-', '.'])
            sanitized_arguments.append(sanitized_arg)
    else:
        sanitized_arguments = []

    # 3. Use subprocess.run with argument lists (not shell=True).
    try:
        process = subprocess.run([command] + sanitized_arguments, capture_output=True, text=True, check=False)  # check=False allows us to handle non-zero exit codes

        return process.returncode, process.stdout, process.stderr

    except FileNotFoundError:
        print(f"Error: Command '{command}' not found.")
        return None, None, None
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return None, None, None


# Example usage:
if __name__ == '__main__':
    # Safe example:
    return_code, stdout, stderr = execute_command('ls', ['-l', '/tmp'])
    if return_code is not None:
        print(f"Return Code: {return_code}")
        print(f"Stdout: {stdout}")
        print(f"Stderr: {stderr}")

    # Another safe example:
    return_code, stdout, stderr = execute_command('grep', ['example', '/tmp/test.txt'])
    if return_code is not None:
        print(f"Return Code: {return_code}")
        print(f"Stdout: {stdout}")
        print(f"Stderr: {stderr}")

    # Unsafe example (command not in allowlist):
    return_code, stdout, stderr = execute_command('rm', ['-rf', '/tmp/*'])  # This will be blocked.
    if return_code is None:
        print("Command was blocked due to not being in the allowlist.")

    # Example with potentially unsafe input (but sanitized):
    user_input = "file; rm -rf /"  # Simulate user input
    return_code, stdout, stderr = execute_command('grep', [user_input, '/tmp/test.txt']) # The semicolon and other characters will be removed.
    if return_code is not None:
        print(f"Return Code: {return_code}")
        print(f"Stdout: {stdout}")
        print(f"Stderr: {stderr}")

