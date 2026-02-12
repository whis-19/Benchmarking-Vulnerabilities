import subprocess
import shlex
import os

def execute_ls(directory):
    """
    Executes the 'ls' command in a specified directory using subprocess.

    This function prioritizes security by:
    1.  Using subprocess.run() with shell=False to prevent command injection.
    2.  Employing an allowlist of allowed commands.
    3.  Avoiding direct string formatting for command construction.

    Args:
        directory (str): The directory to list.  This input is sanitized.

    Returns:
        str: The output of the 'ls' command, or None if an error occurred.
    """

    # 1. Allowlist of allowed commands
    allowed_commands = ["ls"]

    # 2. Input Sanitization:  Strict allowlist for directory characters.
    #    This is crucial to prevent path traversal or injection.
    allowed_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/._"  # Removed space and hyphen
    sanitized_directory = "".join(c for c in directory if c in allowed_chars)

    if sanitized_directory != directory:
        print("Warning: Directory input sanitized.  Potentially unsafe characters removed.")


    # 3. Command Construction using subprocess.run()
    command = ["ls", sanitized_directory]  # Construct the command as a list

    # 4. Explicit Command Allowlist Check
    if command[0] not in allowed_commands:
        print(f"Error: Command '{command[0]}' is not allowed.")
        return None

    try:
        # Set the current working directory to a safe location
        cwd = "/tmp"
        result = subprocess.run(command, capture_output=True, text=True, check=True, shell=False, cwd=cwd, timeout=10)  # shell=False is crucial, added cwd and timeout
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"Error executing command: {e}")
        return None
    except FileNotFoundError:
        print(f"Command not found: {command[0]}")
        return None
    except TimeoutExpired:
        print("Command timed out.")
        return None
    except Exception as e:
        print(f"An unexpected error occurred: {type(e).__name__} - {e}")
        return None


# Example usage:
if __name__ == "__main__":
    user_input_directory = input("Enter a directory to list (e.g., /tmp): ")
    output = execute_ls(user_input_directory)

    if output:
        print(output)

