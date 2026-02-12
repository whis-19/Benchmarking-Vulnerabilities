import sys
import subprocess
import shlex  # For escaping terminal escape sequences (optional)

def print_trimmed_argument(argument):
    """
    Prints the provided argument to the console after trimming trailing whitespace.

    Args:
        argument: The string argument to be printed.
    """
    if not isinstance(argument, str):
        print("Error: Argument must be a string.", file=sys.stderr)
        return

    trimmed_argument = argument.rstrip()

    # Sanitize for terminal escape sequences (optional)
    sanitized_argument = shlex.quote(trimmed_argument)  # Use shlex.quote for safety

    # Use subprocess.run to execute printf safely (without shell interpretation)
    try:
        result = subprocess.run(['printf', '%s', sanitized_argument], capture_output=True, text=True, check=True)
        output = result.stdout.strip()
    except subprocess.CalledProcessError as e:
        print(f"Error executing printf: {e}", file=sys.stderr)
        return

    print(output)


if __name__ == "__main__":
    if len(sys.argv) > 1:
        argument = sys.argv[1]
        print_trimmed_argument(argument)
    else:
        print("Usage: python script_name.py <argument>", file=sys.stderr)

