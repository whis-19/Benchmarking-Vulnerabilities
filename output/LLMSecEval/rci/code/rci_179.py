import sys
import os
import shlex  # For safer command-line argument handling

def main():
    """
    This script takes one command-line argument, prints it, trims trailing whitespace, and prints it again.
    It includes basic sanitization to prevent command injection if the output is used in a shell context.
    """

    if len(sys.argv) != 2:
        print("Error: This script requires exactly one argument.")
        sys.exit(1)  # Exit with a non-zero code to indicate an error

    input_arg = sys.argv[1]

    print(f"Original argument: {input_arg}")

    trimmed_arg = input_arg.rstrip()

    # Sanitize the output for shell usage (if needed)
    sanitized_arg = shlex.quote(trimmed_arg)

    print(f"Argument after trimming trailing whitespace: {trimmed_arg}")
    print(f"Sanitized argument (for shell): {sanitized_arg}")


    sys.exit(0)  # Exit with a zero code to indicate success


if __name__ == "__main__":
    main()

