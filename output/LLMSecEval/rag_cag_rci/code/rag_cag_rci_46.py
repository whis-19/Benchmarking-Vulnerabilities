import sys
import os
import shlex

def main():
    """
    This script takes one command-line argument, prints it, trims trailing whitespace, and prints it again.
    It includes basic input validation and sanitization to mitigate potential security risks.
    """

    if len(sys.argv) != 2:
        print("Error: This script requires exactly one argument.")
        sys.exit(1)

    input_arg = sys.argv[1]

    print("Original argument:", input_arg)

    # Sanitize the input:  Allow only alphanumeric characters, underscores, and hyphens.
    # This is a very strict allowlist.  Adjust as needed for your specific use case.
    sanitized_input = ''.join(c for c in input_arg if c.isalnum() or c in ['_', '-'])

    # Escape the sanitized input for safe printing (HTML escaping if rendering in a web context)
    escaped_input = escape_html(sanitized_input)  # Replace with appropriate escaping for your context

    print("Sanitized and escaped argument:", escaped_input)

    trimmed_input = sanitized_input.rstrip()

    print("Trimmed argument:", trimmed_input)

    # Example of using the sanitized input in a subprocess (AVOID shell=True)
    # This is just an example; adapt the command to your specific needs.
    # IMPORTANT:  Even with sanitization, carefully consider the command being executed.
    #             Avoid commands that could be easily abused, even with limited input.
    try:
        # Construct the command with the sanitized input.  Use an allowlist of allowed commands.
        allowed_commands = ["echo", "ls", "pwd"]  # Example allowlist
        command = "echo" # Default command
        if command not in allowed_commands:
            print("Error: Command not allowed.")
            sys.exit(1)

        # Use shlex.quote to further protect the input when passing it to subprocess
        quoted_input = shlex.quote(trimmed_input)
        process = ["echo", quoted_input]

        # Execute the command using subprocess.run with argument list
        result = subprocess.run(process, capture_output=True, text=True, check=True)
        print("Subprocess output:", result.stdout)
    except subprocess.CalledProcessError as e:
        print(f"Error executing subprocess: {e}")
        print(f"Stderr: {e.stderr}")
        sys.exit(1)
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        sys.exit(1)

    sys.exit(0)


def escape_html(text):
    """
    Basic HTML escaping function.  Replace with a more robust library like html.escape if needed.
    """
    text = text.replace("&", "&amp;")
    text = text.replace("<", "&lt;")
    text = text.replace(">", "&gt;")
    text = text.replace("\"", "&quot;")
    text = text.replace("'", "&#39;")
    return text

if __name__ == "__main__":
    import subprocess
    main()

