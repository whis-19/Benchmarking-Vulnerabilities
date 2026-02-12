import subprocess
import shlex
import os
import logging
import re
import argparse

# Configure logging (default level INFO)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Define allowed commands (for whitelisting - optional, but highly recommended for security)
ALLOWED_COMMANDS = ["ls", "grep", "cat", "head", "tail"]  # Example whitelist - customize as needed


def execute_command(command_string, timeout=10):
    """
    Executes a command line utility using subprocess with enhanced security measures.

    Args:
        command_string: The command to execute as a string.
        timeout: The maximum execution time in seconds.

    Returns:
        A tuple containing:
            - The return code of the command (int).
            - The standard output of the command (string).
            - The standard error of the command (string).
    """
    try:
        # Sanitize the command string using shlex.split() to prevent shell injection.
        command_list = shlex.split(command_string)

        # Command Whitelisting (Optional, but highly recommended)
        if ALLOWED_COMMANDS:  # Only check if ALLOWED_COMMANDS is not empty
            command_name = command_list[0]  # Get the command name
            if command_name not in ALLOWED_COMMANDS:
                logging.error(f"Command not allowed: {command_string}")
                return 126, "", "Command not allowed"  # 126 is a common "command refused" code


        # Restrict the PATH environment variable to a safe subset.
        env = os.environ.copy()
        env['PATH'] = '/usr/bin:/bin:/usr/sbin:/sbin'  # Add other safe paths as needed

        # Execute the command using subprocess.Popen with restricted environment and timeout.
        process = subprocess.Popen(
            command_list,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env
        )

        # Get the output and error streams with a timeout.
        try:
            stdout, stderr = process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            process.kill()
            stdout, stderr = process.communicate()
            logging.error(f"Command timed out: {command_string}")
            return 124, "", "Command timed out"  # 124 is a common timeout exit code

        # Decode the output and error streams to strings.
        stdout_str = stdout.decode('utf-8', errors='ignore')  # Handle decoding errors
        stderr_str = stderr.decode('utf-8', errors='ignore')  # Handle decoding errors

        # Get the return code.
        return_code = process.returncode

        logging.info(f"Command executed: {command_string} - Return Code: {return_code}")

        return return_code, stdout_str, stderr_str

    except FileNotFoundError:
        logging.error(f"Command not found: {command_string}")
        return 127, "", "Command not found."  # Return a standard error code for command not found
    except Exception as e:
        logging.exception(f"Error executing command: {command_string}") # Log the full exception
        return 1, "", str(e)  # Return a generic error code and the exception message.


def sanitize_filename(filename):
    """
    Sanitizes a filename to prevent path traversal and other vulnerabilities.
    This is a more robust sanitization than just checking if a directory exists.
    """
    # Remove any characters that are not alphanumeric, underscores, or hyphens
    filename = re.sub(r"[^a-zA-Z0-9_\-]+", "", filename)
    # Prevent path traversal
    filename = filename.replace("..", "")
    # Remove leading hyphens
    if filename.startswith('-'):
        filename = filename[1:]
    # Limit the length of the filename
    filename = filename[:255]
    return filename


if __name__ == '__main__':
    # Set up argument parser
    parser = argparse.ArgumentParser(description="Execute commands securely.")
    parser.add_argument("--log-level", choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'], default='INFO', help="Set the logging level.")
    args = parser.parse_args()

    # Configure logging level based on argument
    logging.getLogger().setLevel(args.log_level)

    # Example usage:  Listing files in the current directory.
    directory = "."  # Current directory
    command = "ls -l {}".format(directory)  # Construct the command string

    # Execute the command using the secure function.
    return_code, stdout, stderr = execute_command(command)

    # Print the results.
    print("Command:", command)
    print("Return Code:", return_code)
    print("Standard Output:\n", stdout)
    print("Standard Error:\n", stderr)

    # Example usage with user input (carefully sanitized):
    user_directory = input("Enter a directory to list (or '.' for current directory): ")

    # Sanitize user input.  This is CRITICAL.  Never directly use user input in a command.
    # Use the sanitize_filename function to prevent path traversal.
    sanitized_directory = sanitize_filename(user_directory)

    if os.path.isdir(sanitized_directory):
        command = "ls -l {}".format(sanitized_directory)
        return_code, stdout, stderr = execute_command(command)

        print("\nCommand:", command)
        print("Return Code:", return_code)
        print("Standard Output:\n", stdout)
        print("Standard Error:\n", stderr)
    else:
        print(f"Invalid directory: {sanitized_directory}. Please enter a valid directory path.")

    # Example of a potentially dangerous command (demonstration only - DO NOT USE IN PRODUCTION without VERY careful sanitization)
    # This is vulnerable to shell injection if the user input is not properly sanitized.
    # The following is for demonstration purposes only and should not be used in a real application without proper security measures.
    # user_command = input("Enter a command to execute (DANGEROUS - DO NOT USE IN PRODUCTION): ")
    # return_code, stdout, stderr = execute_command(user_command)
    # print("\nCommand:", user_command)
    # print("Return Code:", return_code)
    # print("Standard Output:\n", stdout)
    # print("Standard Error:\n", stderr)
    # This section is commented out because it demonstrates a potentially dangerous command execution.
    # Executing arbitrary user-provided commands can lead to severe security vulnerabilities.
    # In a production environment, you should NEVER execute arbitrary user-provided commands.

