import subprocess
import shlex
import os
import logging

# Configure logging (replace with your preferred logging setup)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


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

    MAX_PATH_LENGTH = 2048  # Example limit

    if len(directory) > MAX_PATH_LENGTH:
        logging.error(f"Directory path too long: {directory}")
        return None

    # Check if the directory exists before calling ls (potential race condition)
    if not os.path.exists(directory):
        logging.warning(f"Directory not found (before ls call): {directory}")  # Use WARNING level
        return None

    try:
        # Use shlex.quote to properly escape the directory path.  This prevents
        # shell injection if the directory name contains special characters.
        quoted_directory = shlex.quote(directory)

        # Construct the command as a list of arguments.  This is the safest way
        # to use subprocess.  Use -d to avoid following symlinks.
        command = ["ls", "-d", quoted_directory]

        # Execute the command using subprocess.run with capture_output=True to
        # capture the output and error streams.  check=True raises an exception
        # if the command returns a non-zero exit code.
        result = subprocess.run(command, capture_output=True, text=True, check=True)

        # Return the standard output.
        return result.stdout

    except subprocess.CalledProcessError as e:
        logging.error(f"Error executing ls: {e}")
        logging.error(f"Stderr: {e.stderr}")  # Print the error message from stderr
        return None
    except PermissionError as e:
        logging.warning(f"Permission denied: {e}")  # Use WARNING level
        return None
    except FileNotFoundError as e:
        logging.warning(f"Directory not found (ls call): {e}")  # Use WARNING level
        return None
    except Exception as e:
        logging.exception(f"An unexpected error occurred: {e}")  # Use logging.exception to include traceback
        return None


def list_directory_safely(directory="."):
    """Lists files in a directory using os.listdir and os.stat.

    Args:
        directory (str, optional): The directory to list. Defaults to ".".

    Returns:
        str: A formatted string of file information, or None if an error occurred.
    """
    MAX_PATH_LENGTH = 2048

    if len(directory) > MAX_PATH_LENGTH:
        logging.error(f"Directory path too long: {directory}")
        return None

    try:
        if not os.path.isdir(directory):  # Check if it's a directory
            logging.warning(f"Not a directory or does not exist: {directory}")
            return None

        files = os.listdir(directory)
        file_info = []
        for filename in files:
            filepath = os.path.join(directory, filename)
            try:
                stat_info = os.stat(filepath)  # Get file stats
                file_info.append((filename, stat_info)) # Store filename and stat info
            except OSError as e:
                logging.warning(f"Could not stat {filepath}: {e}") # Log if stat fails

        # Format the output (you'll need to define how you want to format it)
        output = "\n".join([f"{filename}: Size={stat_info.st_size} bytes, Modified={stat_info.st_mtime}" for filename, stat_info in file_info])
        return output

    except PermissionError as e:
        logging.warning(f"Permission denied: {e}")
        return None
    except Exception as e:
        logging.exception(f"An unexpected error occurred: {e}")
        return None


if __name__ == "__main__":
    # Example usage of execute_ls_safely:
    print("--- Using execute_ls_safely (ls command) ---")
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

    # Example with a very long directory name (DoS prevention):
    output = execute_ls_safely("A" * 3000)
    if output is None:
        print("Successfully prevented listing a very long directory name.")

    # Example usage of list_directory_safely:
    print("\n--- Using list_directory_safely (os.listdir and os.stat) ---")
    output = list_directory_safely()  # List the current directory
    if output:
        print("Files in current directory:")
        print(output)

    # Example with a specific directory:
    output = list_directory_safely("/tmp")  # List the /tmp directory
    if output:
        print("Files in /tmp directory:")
        print(output)

    # Example with a directory name that might contain spaces or special characters:
    output = list_directory_safely("directory with spaces") # This will treat "directory with spaces" as a literal directory name.
    if output:
        print("Files in 'directory with spaces':")
        print(output)
    else:
        print("'directory with spaces' likely does not exist or is not accessible.")

    # Example with a directory that doesn't exist:
    output = list_directory_safely("nonexistent_directory")
    if output:
        print("Files in nonexistent_directory:")
        print(output)
    else:
        print("Failed to list nonexistent_directory (as expected).")

    # Example with a very long directory name (DoS prevention):
    output = list_directory_safely("A" * 3000)
    if output is None:
        print("Successfully prevented listing a very long directory name.")

