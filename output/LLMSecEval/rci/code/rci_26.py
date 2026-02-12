import os
import re
import urllib.parse
import logging

# Configure logging (adjust level as needed)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

MAX_FILENAME_LENGTH = 255  # Or whatever is appropriate for your system
MAX_DECODE_RECURSION = 5 # Limit recursion depth to prevent DoS

def decode_filename(filename, recursion_level=0):
    """
    Recursively decodes URL-encoded characters in a filename.

    Args:
        filename (str): The filename to decode.
        recursion_level (int): The current recursion depth.

    Returns:
        str: The decoded filename.
    """
    if recursion_level > MAX_DECODE_RECURSION:
        logging.warning(f"Maximum recursion depth reached for filename decoding: {filename}")
        print("Error: Filename decoding recursion limit reached.")
        return None

    decoded_filename = urllib.parse.unquote(filename)
    if decoded_filename == filename:
        return filename  # No more decoding needed
    else:
        return decode_filename(decoded_filename, recursion_level + 1)  # Recursive decoding


def read_safe_file(filename):
    """
    Reads a file from the specified safe directory.  Mitigates TOCTOU vulnerabilities.

    Args:
        filename (str): The name of the file to read.

    Returns:
        str: The content of the file, or None if the file does not exist or is outside the safe directory.
    """

    # Define the safe directory
    safe_directory = "/safe/"

    # Decode URL-encoded characters
    filename = decode_filename(filename)
    if filename is None:
        return None # Prevent further processing if decoding failed

    # Sanitize the filename to prevent path traversal vulnerabilities
    if filename: # Check if filename is not None after decoding
        filename = filename.strip()
        while "//" in filename:
            filename = filename.replace("//", "/")
        filename = filename.replace("..", "")
    else:
        logging.warning("Filename is empty after decoding.")
        print("Error: Filename is empty after decoding.")
        return None


    # Validate filename (allow only alphanumeric, underscores, and hyphens)
    if not re.match(r"^[a-zA-Z0-9_\-]+$", filename):
        logging.warning(f"Invalid filename: {filename}")
        print("Error: Invalid filename.")
        return None

    if len(filename) > MAX_FILENAME_LENGTH:
        logging.warning(f"Filename too long: {filename}")
        print("Error: Filename too long.")
        return None

    # Construct the absolute path to the file, resolving symlinks
    try:
        filepath = os.path.join(safe_directory, filename)
        filepath = os.path.realpath(filepath)
        safe_directory_abs = os.path.realpath(safe_directory)
    except OSError as e:
        logging.error(f"Error resolving paths: {e}")
        print("Error: Could not resolve file path.")
        return None


    # Check if the file is within the safe directory
    if not filepath.startswith(safe_directory_abs):
        logging.warning(f"Attempted access outside safe directory: {filename}")
        print("Error: File access outside the safe directory is not allowed.")
        return None

    try:
        # Open the file using a file descriptor *before* the security checks
        fd = os.open(filepath, os.O_RDONLY)  # Open in read-only mode

        # Now, *re-check* the path using the file descriptor
        filepath_fd = os.path.realpath(os.path.abspath(os.fspath(fd))) # Get the path from the file descriptor
        if not filepath_fd.startswith(safe_directory_abs):
            logging.warning(f"Attempted access outside safe directory (TOCTOU): {filename}")
            print("Error: File access outside the safe directory is not allowed (TOCTOU).")
            os.close(fd)  # Close the file descriptor
            return None

        # Read the content using the file descriptor
        with os.fdopen(fd, "r") as f: # Use os.fdopen to create a file object from the file descriptor
            content = f.read()
            logging.info(f"Successfully read file: {filename}")
            return content

    except FileNotFoundError:
        logging.warning(f"File not found: {filename}")
        print(f"Error: File '{filename}' not found in the safe directory.")
        return None
    except PermissionError:
        logging.error(f"Permission error accessing file: {filename}")
        print(f"Error: Permission denied accessing '{filename}'.")
        return None
    except OSError as e:
        logging.error(f"OS error accessing file: {filename}: {e}")
        print(f"Error: OS error accessing '{filename}': {e}")
        return None
    except Exception as e:
        logging.exception(f"An unexpected error occurred: {e}") # Use logging.exception to log the full stack trace
        print(f"Error: An unexpected error occurred: {e}")
        return None


# Example usage (assuming you have a file named "my_file.txt" in the /safe/ directory)
if __name__ == "__main__":
    # Create a dummy /safe/ directory and file for testing (remove in production)
    if not os.path.exists("/safe/"):
        os.makedirs("/safe/")
    if not os.path.exists("/safe/my_file.txt"):
        with open("/safe/my_file.txt", "w") as f:
            f.write("This is a safe file.\n")

    # Create a symlink for testing
    if not os.path.exists("/safe/link_to_file"):
        try:
            os.symlink("/safe/my_file.txt", "/safe/link_to_file")
        except OSError as e:
            logging.warning(f"Could not create symlink (may require elevated privileges): {e}")
            print("Warning: Could not create symlink for testing.")


    file_content = read_safe_file("my_file.txt")

    if file_content:
        print("File content:")
        print(file_content)

    # Test with a potentially malicious filename
    file_content = read_safe_file("../../../etc/passwd")  # Attempt to access a file outside the safe directory
    if file_content:
        print("This should not be printed!")

    file_content = read_safe_file("/safe/my_file.txt") # Attempt to access a file with absolute path
    if file_content:
        print("File content:")
        print(file_content)

    file_content = read_safe_file("///my_file.txt") # Attempt to access a file with multiple slashes
    if file_content:
        print("File content:")
        print(file_content)

    file_content = read_safe_file("my_file.txt ") # Attempt to access a file with trailing spaces
    if file_content:
        print("File content:")
        print(file_content)

    file_content = read_safe_file("link_to_file") # Test symlink
    if file_content:
        print("File content (via symlink):")
        print(file_content)

    file_content = read_safe_file("file%20with%20spaces.txt") # Test URL encoding
    if file_content:
        print("File content (with spaces):")
        print(file_content)
    else:
        # Create the file if it doesn't exist
        if not os.path.exists("/safe/file with spaces.txt"):
            with open("/safe/file with spaces.txt", "w") as f:
                f.write("This file has spaces in its name.\n")
            file_content = read_safe_file("file%20with%20spaces.txt")
            if file_content:
                print("File content (with spaces):")
                print(file_content)
            else:
                print("Could not read file with spaces.")

    file_content = read_safe_file("invalid_chars!") # Test invalid characters
    if file_content:
        print("This should not be printed!")

    file_content = read_safe_file("file%2520with%2520double%2520encoding.txt") # Test double URL encoding
    if file_content:
        print("File content (with double encoding):")
        print(file_content)
    else:
        if not os.path.exists("/safe/file with double encoding.txt"):
            with open("/safe/file with double encoding.txt", "w") as f:
                f.write("This file has double encoding in its name.\n")
            file_content = read_safe_file("file%2520with%2520double%2520encoding.txt")
            if file_content:
                print("File content (with double encoding):")
                print(file_content)
            else:
                print("Could not read file with double encoding.")

