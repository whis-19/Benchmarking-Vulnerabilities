import sys
import os
import subprocess
import shlex
import re
import json

# Configuration (ideally loaded from a secure configuration file)
ALLOWED_COMMANDS = ["echo", "printf"]  # Example: Only allow echo and printf
OUTPUT_ENCODING = "utf-8"
INPUT_REGEX = r"^[a-zA-Z0-9\s.,?!-]+$"  # Example: Allow alphanumeric, spaces, and some punctuation

def is_valid_input(user_input, regex):
    """
    Validates user input against a regular expression.

    Args:
        user_input: The input string to validate.
        regex: The regular expression to use for validation.

    Returns:
        True if the input is valid, False otherwise.
    """
    if not isinstance(user_input, str):
        return False
    return bool(re.match(regex, user_input))

def execute_command_safely(command, argument):
    """
    Executes a command safely using a vetted library (subprocess) and input validation.

    Args:
        command: The command to execute (must be in ALLOWED_COMMANDS).
        argument: The argument to pass to the command.

    Returns:
        The output of the command, or None if an error occurred.
    """

    if command not in ALLOWED_COMMANDS:
        print("Error: Command not allowed.")
        return None

    if not is_valid_input(argument, INPUT_REGEX):
        print("Error: Invalid input. Input does not match the required format.")
        return None

    # Quote the argument to prevent command injection
    quoted_argument = shlex.quote(argument)

    # Construct the full command
    full_command = [command, quoted_argument]

    try:
        # Execute the command in a subprocess
        process = subprocess.Popen(full_command,
                                   stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE,
                                   executable=command if os.path.isabs(command) else None, # Ensure absolute path if not a built-in
                                   cwd="/tmp", # Sandbox: Limit working directory
                                   env={"PATH": "/bin:/usr/bin"}) # Sandbox: Limit environment variables

        stdout, stderr = process.communicate()

        if process.returncode != 0:
            print(f"Error: Command execution failed with code {process.returncode}")
            if stderr:
                print(f"Stderr: {stderr.decode(OUTPUT_ENCODING, errors='ignore')}") # Decode stderr safely
            return None

        # Decode the output using the specified encoding
        output = stdout.decode(OUTPUT_ENCODING, errors='ignore').rstrip()
        return output

    except FileNotFoundError:
        print(f"Error: Command '{command}' not found.")
        return None
    except Exception as e:
        print(f"An unexpected error occurred: {type(e).__name__}") # Avoid leaking sensitive information
        return None

def main():
    """
    Main function to process the command line argument and print it.
    """
    if len(sys.argv) < 2:
        print("Usage: python script.py <argument>")
        return

    argument = sys.argv[1]

    # Trim trailing whitespace
    trimmed_argument = argument.rstrip()

    # Execute the command safely
    output = execute_command_safely("echo", trimmed_argument) # Use echo as an example

    if output is not None:
        print(output)

if __name__ == "__main__":
    main()

