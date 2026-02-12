import subprocess
import shlex
import os
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def execute_ls_safely(directory="."):
    """
    Executes the 'ls' command safely using subprocess and shlex.

    Args:
        directory (str, optional): The directory to list. Defaults to ".".

    Returns:
        str: The output of the 'ls' command, or None if an error occurred.
    """

    try:
        # Sanitize the directory input using shlex.quote to prevent command injection.
        # This is crucial to prevent malicious users from injecting arbitrary commands.
        sanitized_directory = shlex.quote(directory)

        # Construct the command using f-strings for readability and security.
        # Avoid using string concatenation or format strings directly with user input.
        command = f"ls -l {sanitized_directory}"

        # Use subprocess.run with shell=False for security.  This avoids shell injection.
        # Capture stdout and stderr for error handling.
        result = subprocess.run(shlex.split(command), capture_output=True, text=True, check=True)

        # Return the output of the command.
        return result.stdout

    except subprocess.CalledProcessError as e:
        logging.error(f"Error executing command: {e}")
        logging.error(f"Stderr: {e.stderr}")
        return None
    except Exception as e:
        logging.exception(f"An unexpected error occurred: {e}")  # Use logging.exception for full traceback
        return None


if __name__ == "__main__":
    # Example usage:
    output = execute_ls_safely()  # List the current directory
    if output:
        print(output)

    # Example usage with a specific directory:
    output = execute_ls_safely("/tmp")  # List the /tmp directory
    if output:
        print(output)

    # Example of attempting to pass a potentially malicious directory name:
    # This will be safely handled by shlex.quote.
    output = execute_ls_safely("'; rm -rf /; '")
    if output:
        print(output)
    else:
        print("Command execution failed (as expected due to the malicious input being quoted).")

    # Example of using an environment variable
    # This is generally safer than directly taking user input, but still requires care.
    # Ensure the environment variable is properly sanitized if it comes from an untrusted source.
    if "MY_DIRECTORY" in os.environ:
        directory_from_env = os.environ["MY_DIRECTORY"]
        # SANITIZE THE ENVIRONMENT VARIABLE HERE!
        sanitized_directory_from_env = shlex.quote(directory_from_env)
        output = execute_ls_safely(sanitized_directory_from_env)
        if output:
            print(f"Listing directory from environment variable MY_DIRECTORY: {output}")
        else:
            print(f"Failed to list directory from environment variable MY_DIRECTORY.")
    else:
        print("Environment variable MY_DIRECTORY not set.")

