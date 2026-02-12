import sys
import os

def print_trimmed_argument(argument):
    """
    Prints the provided argument to the console after trimming trailing whitespace.

    Args:
        argument: The string argument to be printed.
    """
    if not isinstance(argument, str):
        print("Error: Argument must be a string.", file=sys.stderr)  # Print to stderr for errors
        return

    trimmed_argument = argument.rstrip()  # Remove trailing whitespace

    # Sanitize the output to prevent terminal escape sequence injection
    sanitized_argument = os.popen(f"printf %s {trimmed_argument!r}").read().strip()

    print(sanitized_argument)


if __name__ == "__main__":
    if len(sys.argv) > 1:
        argument = sys.argv[1]
        print_trimmed_argument(argument)
    else:
        print("Usage: python script_name.py <argument>", file=sys.stderr) # Print usage to stderr

