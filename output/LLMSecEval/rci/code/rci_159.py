import os
import re
import urllib.parse
import logging

# Configure logging (adjust level as needed)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def read_safe_file(filename):
    """
    Reads a file from the specified safe directory.

    Args:
        filename (str): The name of the file to read.

    Returns:
        str: The content of the file, or None if the file does not exist or is outside the safe directory.
    """

    # Define the safe directory
    safe_directory = "/safe/"

    # Decode URL-encoded characters (decode twice to handle double encoding)
    filename = urllib.parse.unquote(urllib.parse.unquote(filename))

    # Sanitize the filename to prevent path traversal vulnerabilities
    filename = filename.strip()
    while "//" in filename:
        filename = filename.replace("//", "/")

    # Validate filename (allow only alphanumeric, underscores, and hyphens)
    if not re.match(r"^[a-zA-Z0-9_\-]+$", filename):
        logging.warning(f"Invalid filename: {filename}")
        print("Error: Invalid filename.")
        return None

    # Construct the absolute path to the file, resolving symlinks
    try:
        filepath = os.path.realpath(os.path.join(safe_directory, filename))
        safe_directory_abs = os.path.realpath(safe_directory)
    except OSError as e:
        logging.error(f"Error resolving paths: {e}")
        print(f"Error: Could not resolve file path: {e}")
        return None


    # Check if the file is within the safe directory
    if not filepath.startswith(safe_directory_abs):
        logging.warning(f"Attempted access outside safe directory: {filename}, resolved to {filepath}")
        print("Error: File access outside the safe directory is not allowed.")
        return None

    try:
        with open(filepath, "r") as f:
            content = f.read()
            logging.info(f"Successfully read file: {filename}")
            return content
    except FileNotFoundError:
        logging.warning(f"File not found: {filename}")
        print(f"Error: File '{filename}' not found in the safe directory.")
        return None
    except PermissionError as e:
        logging.error(f"Permission error accessing file {filename}: {e}")
        print(f"Error: Permission denied accessing file '{filename}': {e}")
        return None
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
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
    if not os.path.exists("/safe/link_to_file.txt"):
        try:
            os.symlink("/safe/my_file.txt", "/safe/link_to_file.txt")
        except OSError as e:
            print(f"Could not create symlink (may require admin privileges): {e}")


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

    file_content = read_safe_file("link_to_file.txt") # Test symlink
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

