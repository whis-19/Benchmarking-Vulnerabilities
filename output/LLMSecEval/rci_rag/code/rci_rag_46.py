import sys
import os
import re
import subprocess
import shlex
import logging

# Configure logging (example)
logging.basicConfig(filename='script.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def main():
    """
    This script takes a single command-line argument, validates it,
    prints it, trims trailing whitespace, and then echoes it using subprocess.
    """

    if len(sys.argv) != 2:
        print("Error: This script requires exactly one argument.  Please provide a single string as input.  The script received {} arguments.".format(len(sys.argv) - 1))
        sys.exit(1)

    input_arg = sys.argv[1]

    # Input validation using a strict allowlist.  This is crucial for security.
    # Only allow alphanumeric characters, underscores, hyphens, and periods.
    # This prevents command injection vulnerabilities.
    if not re.match(r"^[a-zA-Z0-9_\-\.]+$", input_arg):
        print("Error: Invalid input.  The argument must contain only alphanumeric characters, underscores, hyphens, and periods.  The provided input was: {}".format(input_arg))
        sys.exit(1)

    # Add a length limit to prevent DoS
    if len(input_arg) > 256:
        print("Error: Input argument is too long. Maximum length is 256 characters.")
        sys.exit(1)

    # Consider removing these print statements in a production environment
    # to prevent information disclosure.  Instead, use logging.
    logging.info("Argument received: {}".format(input_arg))
    #print("Argument: {}".format(input_arg))

    trimmed_input = input_arg.rstrip()

    # Consider removing this print statement in a production environment
    # to prevent information disclosure.  Instead, use logging.
    logging.info("Trimmed argument: {}".format(trimmed_input))
    #print("Trimmed argument: {}".format(trimmed_input))

    # Example of constructing a command with the (validated) input.
    # Even with validation, it's best to use shlex.quote to further protect against
    # unexpected behavior.  However, since we have a very strict allowlist,
    # this is less critical in this specific example.  But it's a good habit.
    #
    # IMPORTANT:  This example is for demonstration purposes only.  Executing
    # arbitrary commands based on user input is inherently dangerous, even with
    # validation.  In a real-world scenario, you should avoid this pattern
    # whenever possible.  If you must execute external commands, use a very
    # limited set of pre-defined commands and arguments, and avoid using user
    # input directly in the command string.

    # Constructing a command using the validated input (demonstration only - be careful!)
    # Use shlex.quote for defense-in-depth.  It escapes any special characters that
    # might still be present in the input after validation, preventing them from
    # being interpreted by the shell.
    quoted_input = shlex.quote(trimmed_input)
    command = ["echo", quoted_input]  # Example: echo the input.  This is a simple example to demonstrate how to execute a command with validated input. `echo` simply prints the input to the console.

    # Execute the command using subprocess.  Use subprocess.run with shell=False
    # and a list of arguments to avoid shell injection vulnerabilities.
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        print("Command output: {}".format(result.stdout))
        logging.info("Command executed successfully. Output: {}".format(result.stdout))
    except subprocess.CalledProcessError as e:
        print("Error executing command: {}".format(e))
        print("Command output (stderr): {}".format(e.stderr))
        logging.error("Error executing command: {}".format(e), exc_info=True) # Log the full exception
        logging.error("Command output (stderr): {}".format(e.stderr))
        sys.exit(1)

    sys.exit(0)

if __name__ == "__main__":
    main()

