import subprocess
import shlex
import os

def executeCommand():
    '''
    Read a command from a user input, validate it, and execute it securely.
    '''

    command_string = input("Enter a command to execute: ")

    # 1. Input Sanitization and Validation:  Use shlex.split to handle quoting and escaping
    try:
        command_list = shlex.split(command_string)
    except ValueError as e:
        print(f"Invalid command syntax: {e}")
        return

    if not command_list:  # Handle empty input
        print("No command entered.")
        return

    # 2.  Command Whitelisting (Crucial for Security):
    #    Define a list of allowed commands.  This is the most important security measure.
    allowed_commands = ["ls", "pwd", "echo", "cat", "head", "tail", "grep", "find"]  # Example whitelist

    if command_list[0] not in allowed_commands:
        print(f"Command '{command_list[0]}' is not allowed.")
        return

    # 3.  Further Argument Validation (Example - Limit file access):
    #    Implement checks on arguments to prevent malicious file access or other dangerous operations.
    #    This is highly dependent on the allowed commands.

    if command_list[0] == "cat":
        if len(command_list) > 1:
            filepath = command_list[1]
            # Check if the file path is within an allowed directory.  This is a critical security check.
            allowed_directory = "/tmp"  # Example: Only allow access to files in /tmp
            if not os.path.abspath(filepath).startswith(allowed_directory):
                print(f"Access to file '{filepath}' is not allowed.  Must be within '{allowed_directory}'.")
                return
        else:
            print("cat requires a filename argument.")
            return

    if command_list[0] == "find":
        # Example: Limit the search depth to prevent resource exhaustion
        max_depth = 3
        if "-maxdepth" in command_list:
            try:
                depth_index = command_list.index("-maxdepth") + 1
                depth = int(command_list[depth_index])
                if depth > max_depth:
                    print(f"Maximum search depth allowed is {max_depth}.")
                    return
            except (ValueError, IndexError):
                print("Invalid -maxdepth argument.")
                return


    # 4.  Execute the Command with subprocess.run (Recommended):
    try:
        result = subprocess.run(command_list, capture_output=True, text=True, check=True, timeout=10)  # Added timeout
        print("Command Output:\n", result.stdout)
        if result.stderr:
            print("Command Error:\n", result.stderr)

    except subprocess.CalledProcessError as e:
        print(f"Command failed with error: {e}")
        print("Error Output:\n", e.stderr)
    except FileNotFoundError:
        print(f"Command '{command_list[0]}' not found.")
    except subprocess.TimeoutExpired:
        print("Command timed out.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")


# Example usage:
if __name__ == "__main__":
    executeCommand()

