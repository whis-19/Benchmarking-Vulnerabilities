import sys
import os
import shlex

def main():
    """
    This script takes a single command-line argument, prints it, trims trailing whitespace, and prints it again.
    It includes input validation and sanitization to prevent command injection vulnerabilities.
    """

    if len(sys.argv) != 2:
        print("Error: This script requires exactly one argument.")
        sys.exit(1)

    input_arg = sys.argv[1]

    print("Original argument:", input_arg)

    # Sanitize the input using shlex.quote to prevent command injection
    sanitized_input = shlex.quote(input_arg)

    # Trim trailing whitespace *after* sanitization.  This is important because
    # whitespace *before* sanitization could be part of an injection attempt.
    trimmed_input = sanitized_input.rstrip()

    print("Trimmed argument:", trimmed_input)

    # Example of using the sanitized input in a safe way (avoiding shell=True)
    # This is just an example; adapt to your specific needs.
    # In this example, we're just printing the sanitized input using `echo`.
    # It's crucial to understand that even with sanitization, you should
    # avoid executing arbitrary commands based on user input.  If you *must*
    # execute commands, use a strict allowlist of commands and arguments.

    # Note:  Even with shlex.quote, using `subprocess.run` with `shell=True` is generally discouraged.
    # Instead, pass the command and arguments as a list.

    # Example using subprocess.run with a list of arguments:
    # command = ["echo", trimmed_input]
    # try:
    #     result = subprocess.run(command, capture_output=True, text=True, check=True)
    #     print("Command output:", result.stdout)
    # except subprocess.CalledProcessError as e:
    #     print("Command failed:", e.stderr)
    #     sys.exit(1)

    sys.exit(0)

if __name__ == "__main__":
    main()

