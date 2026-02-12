import subprocess
import shlex

def execute_ls_safely(directory="."):
    """
    Executes the 'ls' command safely using subprocess.  Avoids using system()
    which is vulnerable to shell injection.

    Args:
        directory (str, optional): The directory to list. Defaults to ".".
                                     This is treated as a literal path, not a pattern.

    Returns:
        str: The output of the 'ls' command, or None if an error occurred.
    """

    try:
        # Use shlex.quote to properly escape the directory path.  This prevents
        # shell injection if the directory name contains special characters.
        quoted_directory = shlex.quote(directory)

        # Construct the command as a list of arguments.  This is the safest way
        # to use subprocess.
        command = ["ls", quoted_directory]

        # Execute the command using subprocess.run with capture_output=True to
        # capture the output and error streams.  check=True raises an exception
        # if the command returns a non-zero exit code.
        result = subprocess.run(command, capture_output=True, text=True, check=True)

        # Return the standard output.
        return result.stdout

    except subprocess.CalledProcessError as e:
        print(f"Error executing ls: {e}")
        print(f"Stderr: {e.stderr}")  # Print the error message from stderr
        return None
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return None


if __name__ == "__main__":
    # Example usage:
    output = execute_ls_safely()  # List the current directory
    if output:
        print("Files in current directory:")
        print(output)

    # Example with a specific directory:
    output = execute_ls_safely("/tmp")  # List the /tmp directory
    if output:
        print("Files in /tmp directory:")
        print(output)

    # Example with a directory name that might contain spaces or special characters:
    output = execute_ls_safely("directory with spaces") # This will treat "directory with spaces" as a literal directory name.
    if output:
        print("Files in 'directory with spaces':")
        print(output)
    else:
        print("'directory with spaces' likely does not exist or is not accessible.")

    # Example with a directory that doesn't exist:
    output = execute_ls_safely("nonexistent_directory")
    if output:
        print("Files in nonexistent_directory:")
        print(output)
    else:
        print("Failed to list nonexistent_directory (as expected).")

