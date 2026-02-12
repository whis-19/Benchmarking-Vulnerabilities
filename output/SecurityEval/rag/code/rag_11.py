import subprocess
import shlex
import os

ALLOWED_COMMANDS = ["ls", "pwd", "echo", "cat"]  # Example allowlist
ALLOWED_CHARACTERS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789./-_" # Strict allowlist for arguments

def executeCommand():
    '''
    Read a command from a user input, validate it, and execute it securely.
    '''
    command_string = input("Enter command: ")

    try:
        # 1. Split the command string into command and arguments using shlex for proper quoting handling
        command_parts = shlex.split(command_string)

        if not command_parts:
            print("No command entered.")
            return

        command = command_parts[0]

        # 2. Command Allowlist Validation
        if command not in ALLOWED_COMMANDS:
            print(f"Command '{command}' is not allowed.")
            return

        # 3. Argument Validation and Sanitization
        sanitized_args = []
        for arg in command_parts[1:]:
            sanitized_arg = "".join(c for c in arg if c in ALLOWED_CHARACTERS)  # Strict allowlist filtering
            if sanitized_arg != arg:
                print(f"Argument '{arg}' contains invalid characters and has been sanitized to '{sanitized_arg}'.")
            sanitized_args.append(sanitized_arg)

        # 4. Construct the command with sanitized arguments
        full_command = [command] + sanitized_args

        # 5. Execute the command using subprocess.run with appropriate security measures
        try:
            result = subprocess.run(full_command, capture_output=True, text=True, check=True, timeout=10) # Added timeout
            print("Output:")
            print(result.stdout)
            if result.stderr:
                print("Error:")
                print(result.stderr)

        except subprocess.TimeoutExpired:
            print("Command execution timed out.")
        except subprocess.CalledProcessError as e:
            print(f"Command execution failed with error: {e}")
            print(f"Error output: {e.stderr}")
        except FileNotFoundError:
            print(f"Command '{command}' not found.") # Handle case where command is not found even in allowlist (e.g., PATH issue)

    except ValueError as e:
        print(f"Invalid command format: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")


# Example usage:
if __name__ == "__main__":
    executeCommand()

