import subprocess
import shlex

def execute_command(command):
    """
    Executes a command using subprocess, adhering to security best practices.

    Args:
        command (str): The command to execute.

    Returns:
        tuple: A tuple containing the return code, stdout, and stderr.
               Returns (-1, None, None) if the command is not allowed.
    """

    # 1. Allowlist of allowed commands.  Crucially important.
    allowed_commands = ["ls", "pwd", "date", "echo"]  # Add more as needed, VERY carefully.

    # 2. Input validation and sanitization.  Use shlex.split to prevent injection.
    try:
        command_list = shlex.split(command)
    except ValueError:
        print("Invalid command syntax.")
        return (-1, None, None)

    if not command_list:
        print("Empty command.")
        return (-1, None, None)

    base_command = command_list[0]

    if base_command not in allowed_commands:
        print(f"Command '{base_command}' is not allowed.")
        return (-1, None, None)

    # 3.  Further sanitization of arguments.  This is an example; adapt to your needs.
    #    This example only allows alphanumeric characters, underscores, hyphens, and dots in arguments.
    #    Adjust the regex as needed for your specific use case, but ALWAYS have a strict allowlist.
    import re
    allowed_chars_regex = re.compile(r"^[a-zA-Z0-9_\-\.]+$")
    for arg in command_list[1:]:
        if not allowed_chars_regex.match(arg):
            print(f"Argument '{arg}' contains invalid characters.")
            return (-1, None, None)

    # 4. Execute using subprocess with argument list and without shell=True.
    try:
        process = subprocess.Popen(command_list, stdout=subprocess.PIPE, stderr=subprocess.PIPE, executable=base_command) # Use executable to avoid path issues
        stdout, stderr = process.communicate()
        return_code = process.returncode

        # Decode stdout and stderr to strings
        stdout_str = stdout.decode("utf-8", errors="ignore") if stdout else ""
        stderr_str = stderr.decode("utf-8", errors="ignore") if stderr else ""

        return (return_code, stdout_str, stderr_str)

    except FileNotFoundError:
        print(f"Command '{base_command}' not found.")
        return (-1, None, None)
    except Exception as e:
        print(f"An error occurred: {e}")
        return (-1, None, None)


if __name__ == '__main__':
    # Example usage:
    command_to_execute = "ls -l"
    return_code, stdout, stderr = execute_command(command_to_execute)

    if return_code == 0:
        print("Command executed successfully.")
        print("Stdout:\n", stdout)
        print("Stderr:\n", stderr)
    else:
        print("Command execution failed.")
        print("Stderr:\n", stderr)

    # Example of an invalid command:
    command_to_execute = "rm -rf /"  # Extremely dangerous, and should be blocked
    return_code, stdout, stderr = execute_command(command_to_execute)

    if return_code == -1:
        print("Command was blocked for security reasons.")

    # Example with invalid characters in arguments:
    command_to_execute = "ls file; rm -rf /"
    return_code, stdout, stderr = execute_command(command_to_execute)

    if return_code == -1:
        print("Command was blocked due to invalid characters in arguments.")

    command_to_execute = "ls valid_file.txt"
    return_code, stdout, stderr = execute_command(command_to_execute)

    if return_code == 0:
        print("Command executed successfully.")
        print("Stdout:\n", stdout)
        print("Stderr:\n", stderr)

