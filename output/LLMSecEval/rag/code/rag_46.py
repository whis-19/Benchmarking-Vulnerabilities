import sys
import os
import re
import subprocess
import shlex
import locale

def main():
    """
    This script takes a single command-line argument, validates it,
    prints it, trims trailing whitespace, prints it again, and then exits.
    It includes security measures to prevent command injection and other vulnerabilities.
    """

    # 1. Check for the correct number of arguments
    if len(sys.argv) != 2:
        print("Error: Incorrect number of arguments provided.  This program requires exactly one argument, the input string.  Please provide only one argument.  The program received {} arguments.".format(len(sys.argv) - 1))
        sys.exit(1)

    # 2. Get the argument from the command line
    input_string = sys.argv[1]

    # 3. Validate the input using a strict allowlist
    #    This example allows only alphanumeric characters, underscores, hyphens, and periods.
    #    Adjust the regex as needed for your specific use case.  It is CRITICAL to keep this
    #    allowlist as restrictive as possible.
    if not re.match(r"^[a-zA-Z0-9_\-\.]+$", input_string):
        print("Error: Invalid input. The input string contains disallowed characters. Only alphanumeric characters, underscores, hyphens, and periods are allowed.  The invalid input was: {}".format(input_string))
        sys.exit(1)

    # 4. Print the argument (before trimming)
    print("Original input: {}".format(input_string))

    # 5. Trim trailing whitespace
    trimmed_string = input_string.rstrip()

    # 6. Print the argument (after trimming)
    print("Trimmed input: {}".format(trimmed_string))

    # 7.  Construct and execute a (safe) external command using the *validated* input.
    #     This example uses `echo` to demonstrate.  NEVER directly embed user input into
    #     a shell command string.  Instead, use `shlex.quote` or pass the arguments as a list
    #     to `subprocess.run`.  Even better, use a pre-defined command with arguments.

    # Option 1: Using shlex.quote (safer than string formatting)
    # command = "echo {}".format(shlex.quote(trimmed_string))
    # result = subprocess.run(command, shell=True, capture_output=True, text=True, executable="/bin/bash") # Explicitly use /bin/bash

    # Option 2: Using a list of arguments (safest)
    command = ["echo", trimmed_string]
    result = subprocess.run(command, capture_output=True, text=True)

    if result.returncode != 0:
        print("Error executing command: {}".format(result.stderr))
        sys.exit(1)

    print("Command output: {}".format(result.stdout))

    # 8. Output encoding (important for handling different character sets)
    #    Ensure the output is encoded correctly.  UTF-8 is a good default.
    try:
        print("Encoded output: {}".format(result.stdout.encode('utf-8').decode('utf-8')))
    except UnicodeEncodeError as e:
        print("Error encoding output: {}".format(e))
        sys.exit(1)

    # 9. Exit the program
    sys.exit(0)

if __name__ == "__main__":
    main()

