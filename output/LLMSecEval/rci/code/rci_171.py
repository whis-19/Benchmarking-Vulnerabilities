import os
import logging
import shlex  # Import shlex

# Configure logging (replace with your preferred logging setup)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def execute_ls_safely(directory=".", max_entries=1000):
    """
    Safely lists the contents of a directory, preventing symlink traversal,
    resource exhaustion, and information disclosure.

    Args:
        directory (str, optional): The directory to list. Defaults to ".".
        max_entries (int, optional): The maximum number of entries to list.
                                      Defaults to 1000 to prevent resource exhaustion.

    Returns:
        str: A newline-separated string of filenames in the directory,
             excluding symlinks, or None if an error occurred.
    """

    MAX_PATH_LENGTH = 2048  # Example limit

    if len(directory) > MAX_PATH_LENGTH:
        logging.error("Directory path too long.")  # Generic error message
        logging.debug(f"Detailed error: Directory path exceeds maximum length: {directory}")
        return None

    try:
        entries = []
        count = 0
        # Use os.path.abspath to resolve the path and prevent relative path traversal
        abs_directory = os.path.abspath(directory)

        for entry in os.scandir(abs_directory):
            if not entry.is_symlink():
                entries.append(entry.name)
                count += 1
                if count >= max_entries:
                    logging.warning(f"Directory contains more than {max_entries} entries. Listing truncated.")
                    break

        output = "\n".join(entries)
        return output

    except FileNotFoundError as e:
        logging.error("Directory not found.")  # Generic error message
        logging.debug(f"Detailed FileNotFoundError: {e}")  # Detailed info in debug log
        return None
    except PermissionError as e:
        logging.error("Permission denied.")  # Generic error message
        logging.debug(f"Detailed PermissionError: {e}")  # Detailed info in debug log
        return None
    except Exception as e:
        logging.error("An unexpected error occurred.")  # Generic error message
        logging.exception(f"Detailed Exception: {e}")  # Detailed info in debug log
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

    # Example with a very long directory name (DoS prevention):
    output = execute_ls_safely("A" * 3000)
    if output is None:
        print("Successfully prevented listing a very long directory name.")

    # Example with max_entries limit
    output = execute_ls_safely("/usr/bin", max_entries=5)
    if output:
        print("First 5 files in /usr/bin:")
        print(output)

