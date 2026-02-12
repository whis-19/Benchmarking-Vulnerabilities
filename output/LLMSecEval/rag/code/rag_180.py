import sys
import subprocess
import os
import shlex
import re
import json

# Configuration (ideally loaded from a secure configuration file)
ALLOWED_COMMANDS = ["echo", "printf"]  # Example: Only allow echo and printf
OUTPUT_ENCODING = "utf-8"
SANDBOX_ENABLED = False  # Set to True to enable sandboxing (requires setup)
CHROOT_PATH = "/opt/sandbox"  # Example path for chroot jail

def is_safe_input(input_string):
    """
    Validates the input string using a regular expression.  This example
    allows alphanumeric characters, spaces, and a few common punctuation marks.
    Adjust the regex as needed for your specific use case.  Be very careful
    about what characters you allow.

    Args:
        input_string: The string to validate.

    Returns:
        True if the input is considered safe, False otherwise.
    """
    # This regex is an example and should be tailored to your specific needs.
    # It's crucial to understand the implications of allowing different characters.
    pattern = r"^[a-zA-Z0-9\s.,?!()-]*$"
    return bool(re.match(pattern, input_string))

def execute_command(command, argument):
    """
    Executes a command with the given argument, with security considerations.

    Args:
        command: The command to execute (must be in ALLOWED_COMMANDS).
        argument: The argument to pass to the command.

    Returns:
        The output of the command, or None if an error occurred.
    """

    if command not in ALLOWED_COMMANDS:
        print("Error: Command not allowed.", file=sys.stderr)
        return None

    if not is_safe_input(argument):
        print("Error: Invalid input.  Input contains disallowed characters.", file=sys.stderr)
        return None

    # Properly quote the argument to prevent command injection.
    # shlex.quote is the preferred method.
    quoted_argument = shlex.quote(argument)

    # Construct the full command.  Keep the command and data separate.
    full_command = [command, quoted_argument]

    try:
        if SANDBOX_ENABLED:
            # Example of using chroot (requires appropriate setup)
            # This is a simplified example and may need adjustments for your environment.
            # Ensure the command and its dependencies are available within the chroot.
            full_command = ["chroot", CHROOT_PATH] + full_command

        # Execute the command using subprocess.run with appropriate security settings.
        result = subprocess.run(
            full_command,
            capture_output=True,
            text=True,
            encoding=OUTPUT_ENCODING,
            errors="replace",  # Handle encoding errors gracefully
            timeout=10,  # Add a timeout to prevent indefinite execution
        )

        if result.returncode != 0:
            print(f"Error: Command failed with return code {result.returncode}", file=sys.stderr)
            print(f"Stderr: {result.stderr}", file=sys.stderr) # Avoid revealing sensitive information
            return None

        return result.stdout.strip()  # Strip whitespace from the output

    except subprocess.TimeoutExpired:
        print("Error: Command timed out.", file=sys.stderr)
        return None
    except FileNotFoundError:
        print("Error: Command not found.", file=sys.stderr)
        return None
    except Exception as e:
        print(f"An unexpected error occurred: {type(e).__name__}", file=sys.stderr) # Avoid revealing sensitive information
        return None


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python script.py <argument>", file=sys.stderr)
        sys.exit(1)

    argument = sys.argv[1]

    # Execute the command (in this example, we're using "echo")
    output = execute_command("echo", argument)

    if output is not None:
        print(output)

