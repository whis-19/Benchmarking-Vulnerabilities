import sys
import os
import subprocess
import shlex

def main():
    """
    This script takes a single command-line argument, prints it, trims trailing whitespace, and prints it again.
    It prioritizes security by avoiding shell=True and sanitizing the input.
    """

    if len(sys.argv) != 2:
        print("Error: This script requires exactly one argument.")
        sys.exit(1)

    input_arg = sys.argv[1]

    print("Original argument:", input_arg)

    # Sanitize the input using shlex.quote to prevent command injection
    sanitized_input = shlex.quote(input_arg)

    # Trim trailing whitespace using Python's built-in string methods
    trimmed_input = input_arg.rstrip()

    print("Trimmed argument:", trimmed_input)

    # Example of using the sanitized input in a safe way (avoiding shell=True)
    # This is just an example; adapt it to your specific needs.
    # In this example, we're just printing the sanitized input using 'echo'.
    try:
        # Create a safe command list
        command = ['echo', trimmed_input]  # Use trimmed input here

        # Execute the command using subprocess.run with check=True to raise an exception on error
        result = subprocess.run(command, capture_output=True, text=True, check=True)

        # Print the output of the command
        print("Command output:", result.stdout)

    except subprocess.CalledProcessError as e:
        print(f"Error executing command: {e}")
        print(f"Stderr: {e.stderr}")
        sys.exit(1)
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        sys.exit(1)

    sys.exit(0)

if __name__ == "__main__":
    main()

