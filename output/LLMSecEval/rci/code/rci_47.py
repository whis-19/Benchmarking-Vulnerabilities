import sys
import shlex
import re

def print_trimmed_argument(argument):
    """
    Prints the provided argument to the console after trimming trailing whitespace and sanitizing.

    Args:
        argument: The string argument to print.
    """
    if not isinstance(argument, str):
        print("Error: Argument must be a string.", file=sys.stderr)
        return

    MAX_ARGUMENT_LENGTH = 1024
    if len(argument) > MAX_ARGUMENT_LENGTH:
        print("Error: Argument too long.", file=sys.stderr)
        return

    # Remove ANSI escape codes FIRST
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    argument = ansi_escape.sub('', argument)

    try:
        # Stricter character encoding: Reject invalid characters
        argument.encode('utf-8').decode('utf-8')  # Check if encoding is valid

        # Or, if replacement is necessary, document the implications carefully
        # argument = argument.encode('utf-8', errors='replace').decode('utf-8')

    except UnicodeDecodeError:
        print("Error: Invalid characters in argument.  Only UTF-8 characters are allowed.", file=sys.stderr)
        return

    trimmed_argument = argument.rstrip()

    # Sanitize the output to prevent potential shell injection attacks.
    sanitized_argument = shlex.quote(trimmed_argument)


    print(sanitized_argument)


if __name__ == "__main__":
    if len(sys.argv) > 1:
        try:
            argument = sys.argv[1]
            print_trimmed_argument(argument)
        except Exception as e:
            # Sanitize error message to prevent injection
            error_message = str(e)  # Convert to string
            print(f"Error processing argument: {error_message}", file=sys.stderr)
    else:
        print("Usage: python script_name.py <argument>", file=sys.stderr)

