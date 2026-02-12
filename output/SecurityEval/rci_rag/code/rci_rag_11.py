import subprocess
import shlex
import os
import re  # Import the regular expression module
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def executeCommand():
    '''
    Read a command from a user input, validate it, and execute it securely.
    '''

    # 1. Allowlist of allowable commands.  This is CRITICAL.
    allowed_commands = ["ls", "grep", "cat", "echo", "pwd"]  # Example commands
    #  Expand this list as needed, but ONLY with commands you explicitly trust.
    #  NEVER include commands like "rm", "mv", "cp", "sudo", etc. without EXTREME caution.

    # 2. Get user input.  This is where the vulnerability lies if not handled carefully.
    user_input = input("Enter a command: ")

    # 3. Input Validation and Sanitization:  Use shlex.split to safely parse the command.
    #    This prevents simple command injection attempts.
    #    Without shlex.split(), a user could use quotes to bypass the space-based splitting and inject commands.
    #    For example, `ls -l "file with spaces; rm -rf /"` would be treated as a single argument if simply splitting on spaces.
    try:
        command_list = shlex.split(user_input)
    except ValueError as e:
        print(f"Invalid command syntax: {e}")
        logging.error(f"Invalid command syntax: {e}")
        return

    # 4. Command Allowlist Check:  Ensure the base command is in the allowed list.
    if not command_list:
        print("No command entered.")
        logging.warning("No command entered.")
        return

    base_command = command_list[0]
    if base_command not in allowed_commands:
        print(f"Command '{base_command}' is not allowed.")
        logging.warning(f"Command '{base_command}' is not allowed.")
        return

    # 5. Argument Sanitization:  Strict allowlist for characters in arguments.
    #    This is crucial to prevent argument injection.
    #    A user could try to inject a command by entering `ls; rm -rf /` as input.  Without proper sanitization, this could potentially delete all files on the system.
    #    Consider context-aware sanitization for each command and argument position for maximum security.
    allowed_chars = "a-zA-Z0-9_.-/"  # Example: alphanumeric, underscore, period, hyphen, forward slash
    allowed_chars_regex = re.compile(f"[^{allowed_chars}]")  # Compile the regex for efficiency
    sanitized_args = []
    for arg in command_list[1:]:  # Skip the base command
        sanitized_arg = allowed_chars_regex.sub("", arg)  # Replace all characters NOT in allowed_chars with ""
        if sanitized_arg != arg:
            print(f"Warning: Argument '{arg}' was sanitized to '{sanitized_arg}'")
            logging.warning(f"Argument '{arg}' was sanitized to '{sanitized_arg}'")
        sanitized_args.append(sanitized_arg)

    # 6.  Specific Command Hardening (Path Traversal and Cat Restriction)
    if base_command == "ls":
        allowed_ls_directory = "/tmp"  # Restrict ls to /tmp (or a more appropriate directory)
        for arg in sanitized_args:
            abs_path = os.path.abspath(os.path.join(allowed_ls_directory, arg))
            if not abs_path.startswith(allowed_ls_directory):
                print(f"Error: 'ls' command is restricted to the directory: {allowed_ls_directory}")
                logging.warning(f"Attempted path traversal with ls: {arg}")
                return
        sanitized_args = [allowed_ls_directory] + sanitized_args  # Always list the allowed directory

    elif base_command == "cat":
        allowed_cat_directory = "/tmp"  # Restrict cat to /tmp (or a more appropriate directory)
        allowed_cat_extensions = [".txt", ".log"]  # Only allow specific file extensions
        if not sanitized_args:
            print("Error: 'cat' command requires a file argument.")
            logging.warning("Cat command used without a file argument.")
            return

        file_path = sanitized_args[0]
        abs_path = os.path.abspath(os.path.join(allowed_cat_directory, file_path))

        if not abs_path.startswith(allowed_cat_directory):
            print(f"Error: 'cat' command is restricted to the directory: {allowed_cat_directory}")
            logging.warning(f"Attempted path traversal with cat: {file_path}")
            return

        file_extension = os.path.splitext(file_path)[1]
        if file_extension not in allowed_cat_extensions:
            print(f"Error: 'cat' command is only allowed for files with extensions: {allowed_cat_extensions}")
            logging.warning(f"Cat command used with disallowed file extension: {file_extension}")
            return

        # Consider reading the file in Python instead of using cat
        # with open(abs_path, 'r') as f:
        #     file_contents = f.read()
        #     print(file_contents)
        # return


    # 7. Validate Argument Count (Example for 'echo')
    if base_command == "echo":
        max_echo_args = 5  # Limit the number of arguments for echo
        if len(sanitized_args) > max_echo_args:
            print(f"Error: 'echo' command accepts a maximum of {max_echo_args} arguments.")
            logging.warning(f"Echo command used with too many arguments: {len(sanitized_args)}")
            return


    # 8. Construct the command with sanitized arguments.
    command_to_execute = [base_command] + sanitized_args

    # 9. Execute the command using subprocess.run with appropriate security measures.
    try:
        # Use subprocess.run for better control and security.
        # 'capture_output=True' captures stdout and stderr.
        # 'text=True' decodes the output as text.
        # 'check=True' raises an exception if the command fails (non-zero exit code).
        # 'timeout=10' sets a timeout to prevent denial-of-service attacks.
        # 'env' provides a clean environment (see below).

        # Create a clean environment (optional, but recommended)
        env = os.environ.copy()
        # Remove potentially harmful environment variables
        env.pop("LD_PRELOAD", None)
        env.pop("DYLD_INSERT_LIBRARIES", None)

        result = subprocess.run(command_to_execute, capture_output=True, text=True, check=True, timeout=10, env=env)

        # Log the successful command execution
        logging.info(f"Command executed successfully: {command_to_execute}")

        # 10. Output Encoding and Display:  Handle output encoding correctly.
        print("Command output:")
        print(result.stdout)
        if result.stderr:
            print("Command error:")
            print(result.stderr)

    except subprocess.CalledProcessError as e:
        print(f"Command failed with error: {e}")
        print(f"Stderr: {e.stderr}")
        logging.error(f"Command failed: {command_to_execute}, Error: {e}, Stderr: {e.stderr}")
    except FileNotFoundError:
        print(f"Command '{base_command}' not found.")
        logging.error(f"Command not found: {base_command}")
    except subprocess.TimeoutExpired:
        print("Command timed out.")
        logging.error(f"Command timed out: {command_to_execute}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        logging.exception(f"An unexpected error occurred: {e}")


# Example usage:
if __name__ == "__main__":
    # Consider running the script with reduced privileges (e.g., using `sudo -u nobody python your_script.py`)
    executeCommand()

