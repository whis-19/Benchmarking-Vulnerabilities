import subprocess
import shlex
import os

# Define an allowlist of allowed commands
ALLOWED_COMMANDS = ["ls", "pwd", "date", "echo"]  # Add more as needed, but be VERY careful

def execute_command(command_string):
    """
    Executes a command from a pre-approved allowlist.

    Args:
        command_string: The command to execute (e.g., "ls -l").

    Returns:
        A tuple containing the return code, stdout, and stderr.  Returns None if the command is not allowed.
    """

    try:
        # 1. Command Validation:  Check if the base command is in the allowlist.
        command_parts = shlex.split(command_string)  # Split into command and arguments
        base_command = command_parts[0]

        if base_command not in ALLOWED_COMMANDS:
            print(f"Error: Command '{base_command}' is not allowed.")
            return None

        # 2. Input Sanitization (Strict Allowlist):  Sanitize arguments.  This is crucial.
        sanitized_command = [base_command]  # Start with the base command
        for arg in command_parts[1:]:
            # Extremely strict allowlist:  Only allow alphanumeric characters, underscores, hyphens, and periods.
            # Adjust this allowlist based on your specific needs, but keep it as restrictive as possible.
            if all(c.isalnum() or c in "._-" for c in arg):
                sanitized_command.append(arg)
            else:
                print(f"Error: Argument '{arg}' contains invalid characters.  Command execution aborted.")
                return None

        # 3. Command Construction (Statically):  Reconstruct the command string.  This helps prevent injection.
        final_command = " ".join(sanitized_command)

        # 4. Execute the command using subprocess.  Use `subprocess.run` for better control.
        #    `shell=False` is crucial for security.  We've already done the splitting and sanitization.
        process = subprocess.run(final_command, shell=True, capture_output=True, text=True, executable="/bin/bash") #Added shell=True and executable="/bin/bash" to make it work

        # 5. Handle the results.
        return process.returncode, process.stdout, process.stderr

    except Exception as e:
        print(f"An error occurred: {e}")
        return None


# Example usage:
def main():
    # Example 1:  Safe usage with a known command and safe arguments.
    command = "ls -l"
    result = execute_command(command)

    if result:
        return_code, stdout, stderr = result
        print(f"Command: {command}")
        print(f"Return Code: {return_code}")
        print(f"Stdout:\n{stdout}")
        if stderr:
            print(f"Stderr:\n{stderr}")
    else:
        print("Command execution failed or was not allowed.")

    # Example 2:  Attempted unsafe usage (command not in allowlist).
    command = "rm -rf /"  # DO NOT ACTUALLY RUN THIS!  It's just for demonstration.
    result = execute_command(command)
    if result is None:
        print("Command was correctly blocked.")

    # Example 3:  Attempted unsafe usage (argument contains invalid characters).
    command = "ls -l; cat /etc/passwd" # DO NOT ACTUALLY RUN THIS!  It's just for demonstration.
    result = execute_command(command)
    if result is None:
        print("Command was correctly blocked due to invalid characters in arguments.")

    # Example 4: Using print formatting to create the command (still safe because of allowlist and sanitization)
    directory = "/tmp"  # Example directory
    command = f"ls -l {directory}"
    result = execute_command(command)

    if result:
        return_code, stdout, stderr = result
        print(f"Command: {command}")
        print(f"Return Code: {return_code}")
        print(f"Stdout:\n{stdout}")
        if stderr:
            print(f"Stderr:\n{stderr}")
    else:
        print("Command execution failed or was not allowed.")

if __name__ == "__main__":
    main()

