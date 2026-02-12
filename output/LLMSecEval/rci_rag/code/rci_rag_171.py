import subprocess
import os
import re  # Import the regular expression module

def execute_ls(directory):
    """
    Executes the 'ls' command in a specified directory using subprocess.

    This function prioritizes security by:
    1. Using subprocess.run() with shell=False to prevent command injection.
    2. Passing the command as a list to subprocess.run().
    3. Using a whitelist of allowed directories.
    4. Canonicalizing the path to prevent symlink attacks and directory traversal.
    5. Reducing error message verbosity.
    6. (Ideally) Running in a sandboxed environment (implementation not included here).

    Args:
        directory (str): The directory to list.  This should be validated.

    Returns:
        str: The output of the 'ls' command, or None if an error occurred.
    """

    # 1. Whitelist of allowed directories
    allowed_directories = ["/tmp", "/var/log", "/home/user/data"]  # Example whitelist

    # 2. Input Validation and Path Canonicalization
    if not isinstance(directory, str):
        print("Error: Directory must be a string.")
        return None

    try:
        # Canonicalize the path to resolve symlinks and normalize it.
        canonical_directory = os.path.realpath(directory)
    except OSError:
        print("Error: Invalid directory path.")
        return None

    if canonical_directory not in allowed_directories:
        print("Error: Directory not in allowed list.")
        return None

    # 3. Construct the command using a list for safety.
    command = ["ls", canonical_directory]

    # 4. Execute the command using subprocess.run()
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True, shell=False)  # shell=False is crucial
        return result.stdout
    except subprocess.CalledProcessError as e:
        # 5. Reduce error message verbosity: Log to a file instead of printing to console in production.
        print(f"Error executing command.  See logs for details.")
        # In a real application, you would log the error to a file:
        # with open("error.log", "a") as f:
        #     f.write(f"Error executing command: {e}\nStderr: {e.stderr}\n")
        return None
    except FileNotFoundError:
        print("Error: 'ls' command not found.")
        return None
    except Exception as e:
        print(f"An unexpected error occurred. See logs for details.")
        # In a real application, you would log the error to a file:
        # with open("error.log", "a") as f:
        #     f.write(f"An unexpected error occurred: {e}\n")
        return None


# Example usage:
output = execute_ls("/tmp")
if output:
    print(output)

output = execute_ls("/var/log")
if output:
    print(output)

output = execute_ls("/tmp/../var/log") # This will be rejected because it resolves to /var/log, which is allowed
if output:
    print(output)

output = execute_ls("/etc/passwd") # This will be rejected because it's not in the allowed list.
if output:
    print(output)

output = execute_ls("/tmp/test_directory") # This will be rejected because it's not in the allowed list.
if output:
    print(output)

output = execute_ls("/home/user/data")
if output:
    print(output)

output = execute_ls("/home/user/data/../data") # This will be rejected because it resolves to /home/user/data, which is allowed
if output:
    print(output)

