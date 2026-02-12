import sys
import subprocess
import shlex

def sanitize_input(input_string, allowed_chars):
    """
    Sanitizes the input string by removing characters not in the allowlist.

    Args:
        input_string: The string to sanitize.
        allowed_chars: A set of allowed characters.

    Returns:
        The sanitized string.
    """
    return ''.join(c for c in input_string if c in allowed_chars)

def process_string(input_string):
    """
    Processes the input string by trimming whitespace and newlines, and null-terminating it.

    Args:
        input_string: The string to process.

    Returns:
        The processed string.  Returns None if an error occurs.
    """

    MAX_LENGTH = 256  # Define a maximum length for the string
    if len(input_string) > MAX_LENGTH:
        print("Error: Input string exceeds maximum length.")
        return None

    # Trim trailing whitespace
    input_string = input_string.rstrip()

    # Trim newlines
    input_string = input_string.replace('\n', '')

    # Null-terminate (simulated in Python) -  This is mostly for C-style string handling,
    # but we can represent it by ensuring no embedded nulls and potentially adding one at the end
    if '\0' in input_string:
        print("Error: Input string contains null characters.")
        return None

    return input_string + '\0'  # Append a null character for representation

def execute_command(command, user_input):
    """
    Executes a pre-defined command with sanitized user input.

    Args:
        command: The command to execute (must be from an allowlist).
        user_input: The user input to pass to the command.

    Returns:
        The output of the command, or None if an error occurred.
    """

    ALLOWED_COMMANDS = ["echo", "printf"]  # Example allowlist of commands

    if command not in ALLOWED_COMMANDS:
        print(f"Error: Command '{command}' is not allowed.")
        return None

    # Define a strict allowlist of characters for the user input
    ALLOWED_CHARS = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-. ")

    sanitized_input = sanitize_input(user_input, ALLOWED_CHARS)

    # Escape the sanitized input for shell execution using shlex.quote
    escaped_input = shlex.quote(sanitized_input)

    # Construct the command with the escaped input
    full_command = [command, escaped_input]

    try:
        # Execute the command using subprocess.run with shell=False for safety
        result = subprocess.run(full_command, capture_output=True, text=True, check=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"Error executing command: {e}")
        print(f"Stderr: {e.stderr}")
        return None
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return None


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python script.py <input_string>")
        sys.exit(1)

    input_string = sys.argv[1]

    if not isinstance(input_string, str):
        print("Error: Input must be a string.")
        sys.exit(1)

    processed_string = process_string(input_string)

    if processed_string is None:
        sys.exit(1)

    print(f"Processed string: {processed_string}")

    # Example usage with command execution (using "echo" as an example)
    output = execute_command("echo", processed_string)  # Use "echo" or "printf" from the allowlist
    if output:
        print(f"Command output: {output}")

