import subprocess
import shlex
import os

def execute_ls_safely(directory="."):
    """
    Executes the 'ls' command safely using subprocess and shlex.

    Args:
        directory (str, optional): The directory to list. Defaults to ".".
                                     This is treated as user input and must be sanitized.

    Returns:
        str: The output of the 'ls' command, or None if an error occurred.
    """

    # Sanitize the directory input using shlex.quote.  This prevents command injection.
    # It's crucial to treat any user-provided input as potentially malicious.
    sanitized_directory = shlex.quote(directory)

    # Construct the command using a list.  This avoids shell injection vulnerabilities.
    command = ["ls", sanitized_directory]

    try:
        # Use subprocess.run with capture_output=True and check=True for security and error handling.
        result = subprocess.run(command, capture_output=True, text=True, check=True, shell=False)  # shell=False is crucial

        # Return the output of the command.
        return result.stdout

    except subprocess.CalledProcessError as e:
        # Handle errors gracefully.  Log the error and return None.
        print(f"Error executing 'ls': {e}")
        print(f"Stderr: {e.stderr}")  # Print stderr for debugging
        return None
    except FileNotFoundError:
        print("Error: 'ls' command not found.")
        return None
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return None


if __name__ == "__main__":
    # Example usage:
    directory_to_list = input("Enter a directory to list (or leave blank for current directory): ")

    # Handle empty input gracefully
    if not directory_to_list:
        directory_to_list = "."

    output = execute_ls_safely(directory_to_list)

    if output:
        print("Output of 'ls':")
        print(output)
    else:
        print("Failed to execute 'ls'.")

    # Example of a potentially dangerous input (demonstrates the importance of sanitization):
    # directory_to_list = "; rm -rf /"  # DO NOT RUN THIS WITHOUT UNDERSTANDING THE RISKS!
    # output = execute_ls_safely(directory_to_list) # This would be VERY BAD without shlex.quote

