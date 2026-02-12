import os
import re
import logging

logging.basicConfig(level=logging.INFO)  # Configure logging

def read_safe_file(filename):
    """
    Reads a file from the /safe/ directory.  Uses whitelisting and canonicalization.

    Args:
        filename: The name of the file to read.

    Returns:
        The content of the file as a string, or None if the file does not exist or an error occurs.
    """

    safe_directory = "/safe/"

    def is_valid_filename(filename):
        """
        Validates the filename using a whitelist approach.
        """
        pattern = r"^[a-zA-Z0-9_.-]+$"  # Allow alphanumeric, underscore, period, and hyphen
        # ^ and $ ensure the entire filename matches the pattern, preventing partial matches.
        return bool(re.match(pattern, filename))

    if not is_valid_filename(filename):
        logging.error(f"Invalid filename: {filename}.  Filename contains disallowed characters.")
        return None

    filepath = os.path.join(safe_directory, filename)
    filepath = os.path.abspath(filepath)  # Normalize the path
    filepath = os.path.realpath(filepath)  # Resolve symbolic links

    # Ensure the safe directory is also canonicalized for accurate comparison
    safe_directory_real = os.path.realpath(safe_directory)

    if not filepath.startswith(safe_directory_real):
        logging.error(f"Path traversal attempt detected: {filepath} is outside the safe directory.")
        return None

    if not os.path.exists(filepath):
        logging.error(f"File '{filepath}' does not exist.")
        return None

    if not os.path.isfile(filepath):
        logging.error(f"'{filepath}' is not a regular file.")
        return None

    try:
        with open(filepath, 'r') as f:
            content = f.read()
            return content
    except FileNotFoundError:
        # This is unlikely to occur because of the os.path.exists check, but included as a defensive measure.
        # A race condition could occur between the check and the open, but it's very rare.
        logging.error(f"File '{filepath}' not found (even after existence check). This is unexpected.")
        return None
    except PermissionError:
        logging.error(f"Permission denied to read file '{filepath}'.")
        return None
    except Exception as e:
        logging.exception(f"An unexpected error occurred while reading file '{filepath}': {e}")  # Log the full exception
        return None


# Example usage:
if __name__ == "__main__":
    # Create the /safe/ directory if it doesn't exist (for testing purposes).
    if not os.path.exists("/safe/"):
        os.makedirs("/safe/")

    # Create a sample file in the /safe/ directory (for testing purposes).
    sample_file = "/safe/my_safe_file.txt"
    with open(sample_file, "w") as f:
        f.write("This is some safe content.\n")

    file_content = read_safe_file("my_safe_file.txt")

    if file_content:
        print("File content:")
        print(file_content)
    else:
        print("Failed to read the file.")

    # Test with an invalid filename (path traversal attempt)
    file_content = read_safe_file("../../../etc/passwd")  # Attempt to read a sensitive file
    if file_content:
        print("File content (attempted path traversal):")
        print(file_content)
    else:
        print("Path traversal attempt prevented.")

    # Test with a non-existent file
    file_content = read_safe_file("non_existent_file.txt")
    if file_content:
        print("File content (non-existent file):")
        print(file_content)
    else:
        print("Non-existent file handled correctly.")

    # Test with a filename containing invalid characters
    file_content = read_safe_file("invalid!filename.txt")
    if file_content:
        print("File content (invalid filename):")
        print(file_content)
    else:
        print("Invalid filename handled correctly.")

    # Test with a symbolic link (create a symlink for testing)
    try:
        os.symlink("/safe/my_safe_file.txt", "/safe/link_to_safe_file.txt")
        # Creating symlinks often requires elevated privileges (e.g., SeCreateSymbolicLinkPrivilege on Windows).
        file_content = read_safe_file("link_to_safe_file.txt")
        if file_content:
            print("File content (via symlink):")
            print(file_content)
        else:
            print("Failed to read file via symlink (as expected).")
    except OSError as e:
        print(f"Could not create symlink (may require elevated privileges): {e}")
    finally:
        try:
            os.remove("/safe/link_to_safe_file.txt") # Clean up the symlink
        except FileNotFoundError:
            pass # It's okay if the symlink wasn't created.

