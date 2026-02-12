import subprocess
import os
import shlex

# Define an allowlist of allowed commands
ALLOWED_COMMANDS = ["ls", "grep", "cat", "head", "tail"]
ALLOWED_FILE_EXTENSIONS = [".txt", ".log", ".csv"]
ALLOWED_FILE_LOCATIONS = ["/var/log", "/tmp"]  # Example allowed locations


def is_path_traversal(path):
    """
    Checks if a given path contains path traversal sequences like "../".
    """
    normalized_path = os.path.normpath(path)
    return ".." in normalized_path


def is_allowed_file_extension(filename):
    """
    Checks if the file extension is in the allowlist.
    """
    _, ext = os.path.splitext(filename)
    return ext.lower() in ALLOWED_FILE_EXTENSIONS


def is_allowed_file_location(filepath):
    """
    Checks if the file path is within the allowed locations.
    """
    absolute_path = os.path.abspath(filepath)
    for allowed_location in ALLOWED_FILE_LOCATIONS:
        if absolute_path.startswith(os.path.abspath(allowed_location)):
            return True
    return False


def execute_command(user_input):
    """
    Executes a command based on user input, with validation and sanitization.
    """
    try:
        # 1. Sanitize and validate the user input
        command_parts = shlex.split(user_input)  # Split into command and arguments

        if not command_parts:
            return "Error: No command provided."

        command = command_parts[0]
        arguments = command_parts[1:]

        # 2. Check if the command is in the allowlist
        if command not in ALLOWED_COMMANDS:
            return f"Error: Command '{command}' is not allowed."

        # 3. Validate file paths in arguments (if any)
        for arg in arguments:
            # Check for path traversal
            if is_path_traversal(arg):
                return "Error: Path traversal detected."

            # Check file extension and location if the argument looks like a file path
            if os.path.exists(arg):  # Check if the file exists before further validation
                if not is_allowed_file_extension(arg):
                    return "Error: File extension not allowed."
                if not is_allowed_file_location(arg):
                    return "Error: File location not allowed."

        # 4. Execute the command using subprocess with argument list (shell=False)
        try:
            result = subprocess.run([command] + arguments, capture_output=True, text=True, timeout=10, check=False)  # Added timeout and check=False
            # check=False prevents raising an exception on non-zero exit codes.
            # timeout prevents the command from running indefinitely.

            if result.returncode == 0:
                return result.stdout
            else:
                return f"Error: Command failed with return code {result.returncode}\n{result.stderr}"

        except subprocess.TimeoutExpired:
            return "Error: Command execution timed out."
        except FileNotFoundError:
            return "Error: Command not found."
        except Exception as e:
            return f"Error: An unexpected error occurred: {str(e)}"

    except Exception as e:
        return f"Error: Input processing error: {str(e)}"


if __name__ == '__main__':
    # Example usage (for testing purposes only)
    user_input = input("Enter a command: ")
    output = execute_command(user_input)
    print(output)

