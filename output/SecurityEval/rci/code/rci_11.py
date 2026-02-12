import subprocess
import shlex
import os
import resource  # For resource limits
import logging  # For logging

# Configure logging
logging.basicConfig(filename='command_execution.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')


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
        logging.error(f"Invalid command syntax: {e}")
        return

    if not command_list:  # Handle empty input
        print("No command entered.")
        logging.warning("No command entered.")
        return

    # 2.  Command Whitelisting (Crucial for Security):
    #    Define a list of allowed commands.  This is the most important security measure.
    allowed_commands = ["ls", "pwd", "cat", "head", "tail", "grep", "find"]  # Example whitelist

    if command_list[0] not in allowed_commands:
        print(f"Command '{command_list[0]}' is not allowed.")
        logging.warning(f"Command '{command_list[0]}' is not allowed.")
        return

    # 3.  Further Argument Validation (Example - Limit file access):
    #    Implement checks on arguments to prevent malicious file access or other dangerous operations.
    #    This is highly dependent on the allowed commands.

    allowed_directory = "/tmp"  # Example: Only allow access to files in /tmp

    def validate_filepath(filepath):
        """Validates that a filepath is within the allowed directory."""
        real_filepath = os.path.realpath(filepath)  # Resolve symbolic links
        if not real_filepath.startswith(allowed_directory):
            print(f"Access to file '{filepath}' is not allowed.  Must be within '{allowed_directory}'.")
            logging.warning(f"Attempted access to file '{filepath}' outside allowed directory.")
            return False
        return True

    if command_list[0] == "cat":
        if len(command_list) > 1:
            filepath = command_list[1]
            if not validate_filepath(filepath):
                return
        else:
            print("cat requires a filename argument.")
            logging.warning("cat requires a filename argument.")
            return

    if command_list[0] == "find":
        # Example: Limit the search depth to prevent resource exhaustion
        allowed_find_args = ["-name", "-type", "-maxdepth"]  # Whitelist find arguments
        # Disallow potentially dangerous arguments
        disallowed_find_args = ["-exec", "-ok", "-delete"]
        for arg in command_list[1:]:
            if arg in disallowed_find_args:
                print(f"Argument '{arg}' is not allowed with find.")
                logging.warning(f"Attempted use of disallowed find argument: {arg}")
                return
            if arg.startswith("-") and arg not in allowed_find_args and arg not in disallowed_find_args:
                print(f"Invalid find argument: {arg}")
                logging.warning(f"Invalid find argument: {arg}")
                return

        max_depth = 3
        if "-maxdepth" in command_list:
            try:
                depth_index = command_list.index("-maxdepth") + 1
                depth = int(command_list[depth_index])
                if depth > max_depth:
                    print(f"Maximum search depth allowed is {max_depth}.")
                    logging.warning(f"Maximum search depth allowed is {max_depth}.")
                    return
            except (ValueError, IndexError):
                print("Invalid -maxdepth argument.")
                logging.warning("Invalid -maxdepth argument.")
                return

        # Validate starting directory for find
        if len(command_list) > 1 and not command_list[1].startswith("-"):  # Check if a directory is specified
            start_dir = command_list[1]
            if not start_dir.startswith(allowed_directory):
                print(f"Find start directory '{start_dir}' is not allowed. Must be within '{allowed_directory}'.")
                logging.warning(f"Find start directory '{start_dir}' is not allowed.")
                return
            real_start_dir = os.path.realpath(start_dir)
            if not real_start_dir.startswith(allowed_directory):
                print(f"Find start directory '{start_dir}' is not allowed. Must be within '{allowed_directory}'.")
                logging.warning(f"Find start directory '{start_dir}' is not allowed.")
                return

    if command_list[0] == "echo":
        #  AVOID ECHO IF POSSIBLE.  This is extremely difficult to sanitize correctly.
        print("Echo is disabled for security reasons.")
        logging.warning("Attempted use of echo.")
        return

    if command_list[0] in ("head", "tail"):
        if len(command_list) > 1:
            filepath = command_list[1]
            if not validate_filepath(filepath):
                return
        else:
            print(f"{command_list[0]} requires a filename argument.")
            logging.warning(f"{command_list[0]} requires a filename argument.")
            return

        # Limit the number of lines
        max_lines = 20
        if "-n" in command_list:
            try:
                lines_index = command_list.index("-n") + 1
                num_lines = int(command_list[lines_index])
                if num_lines > max_lines:
                    print(f"Maximum number of lines allowed is {max_lines}.")
                    logging.warning(f"Maximum number of lines allowed is {max_lines}.")
                    return
            except (ValueError, IndexError):
                print("Invalid -n argument.")
                logging.warning("Invalid -n argument.")
                return

    if command_list[0] == "grep":
        if len(command_list) > 2:
            filepath = command_list[2]  # Pattern is command_list[1], filepath is command_list[2]
            if not validate_filepath(filepath):
                return
        else:
            print("grep requires a pattern and a filename argument.")
            logging.warning("grep requires a pattern and a filename argument.")
            return

        # Limit the complexity of the regular expression (very basic example)
        pattern = command_list[1]
        if len(pattern) > 50:  # Arbitrary limit
            print("Regular expression too complex.")
            logging.warning("Regular expression too complex.")
            return

        # Consider using a safer regex engine or limiting execution time for ReDoS protection


    # 4.  Execute the Command with subprocess.run (Recommended):
    try:
        # Limit resources
        try:
            resource.setrlimit(resource.RLIMIT_CPU, (5, 5))  # 5 seconds CPU time
            resource.setrlimit(resource.RLIMIT_AS, (100 * 1024 * 1024, 100 * 1024 * 1024))  # 100MB memory
            resource.setrlimit(resource.RLIMIT_FSIZE, (1024 * 1024, 1024 * 1024))  # 1MB file size
        except OSError as e:
            print(f"Failed to set resource limits: {e}")
            logging.error(f"Failed to set resource limits: {e}")
            return # Do not execute if resource limits cannot be set

        result = subprocess.run(command_list, capture_output=True, text=True, check=True, timeout=10)  # Added timeout
        print("Command Output:\n", result.stdout)
        if result.stderr:
            print("Command Error:\n", result.stderr)

        logging.info(f"Command executed: {command_list} - Output: {result.stdout} - Error: {result.stderr}")


    except subprocess.CalledProcessError as e:
        print(f"Command failed with error: {e}")
        print("Error Output:\n", e.stderr)
        logging.error(f"Command failed: {command_list} - Error: {e}")
        logging.error(f"Error Output:\n", e.stderr)
    except FileNotFoundError:
        print(f"Command '{command_list[0]}' not found.")
        logging.error(f"Command '{command_list[0]}' not found.")
    except subprocess.TimeoutExpired:
        print("Command timed out.")
        logging.error(f"Command timed out: {command_list}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        logging.exception(f"An unexpected error occurred: {e}")


# Example usage:
if __name__ == "__main__":
    executeCommand()

