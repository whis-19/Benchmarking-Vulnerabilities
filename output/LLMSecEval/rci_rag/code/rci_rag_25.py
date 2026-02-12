import os
import re
import logging

# Configure logging (adjust level as needed)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def read_safe_file(filename):
    """
    Reads a file from the /safe/ directory, ensuring security.

    Args:
        filename (str): The name of the file to read (without path).  
                         Must be a simple filename, not a path.

    Returns:
        str: The content of the file, or None if an error occurred.
    """

    SAFE_DIR = "/safe/"

    # Validate filename:  Reject directory separators, ".." sequences, and multiple dots.
    if not isinstance(filename, str):
        logging.error("Filename must be a string.")
        return None

    if "/" in filename or "\\" in filename:
        logging.error("Filename cannot contain directory separators.")
        return None

    if ".." in filename:
        logging.error("Filename cannot contain '..' sequences.")
        return None

    if filename.count(".") > 1:
        logging.error("Filename cannot contain more than one '.' character.")
        return None

    if not re.match(r"^[a-zA-Z0-9._-]+$", filename):
        logging.error("Filename contains invalid characters.  Only alphanumeric characters, '.', '_', and '-' are allowed.")
        return None

    # Construct the full path.
    filepath = os.path.join(SAFE_DIR, filename)

    # Normalize the path and check for ".." components after normalization.
    normalized_path = os.path.normpath(filepath)
    if not normalized_path.startswith(SAFE_DIR):
        logging.error("Filename resolves to a path outside the safe directory.")
        return None
    
    if ".." in normalized_path.replace(SAFE_DIR, ""):
        logging.error("Filename resolves to a path outside the safe directory (after normalization).")
        return None

    # Check for symbolic links
    if os.path.islink(normalized_path):
        logging.error("Filename is a symbolic link, which is not allowed.")
        return None

    try:
        with open(filepath, "r") as f:
            content = ""
            while True:
                chunk = f.read(4096)  # Read in 4KB chunks
                if not chunk:
                    break
                content += chunk
            logging.info(f"Successfully read file: {filepath}")
            return content
    except FileNotFoundError:
        logging.error(f"File not found: {filepath}")
        return None
    except IOError as e:
        logging.error(f"Could not read file: {filepath} - {e}")
        return None
    except Exception as e:
        logging.exception(f"An unexpected error occurred: {e}") # Log the full exception
        return None


# Example usage (assuming a file named "my_data.txt" exists in /safe/):
if __name__ == "__main__":
    # Ensure the /safe/ directory exists
    if not os.path.exists("/safe/"):
        try:
            os.makedirs("/safe/", mode=0o700)  # Create with restricted permissions
            print("Created /safe/ directory with restricted permissions.")
        except OSError as e:
            print(f"Error creating /safe/ directory: {e}")
            exit()

    # Create a test file
    try:
        with open("/safe/my_data.txt", "w") as f:
            f.write("This is some test data.\n")
    except IOError as e:
        print(f"Error creating test file: {e}")
        exit()


    file_content = read_safe_file("my_data.txt")
    if file_content:
        print("File content:\n", file_content)

    # Example of an invalid filename:
    file_content = read_safe_file("../../../etc/passwd")  # Attempt to access a file outside the safe directory
    if file_content is None:
        print("Attempt to read invalid file was correctly blocked.")

    file_content = read_safe_file("data.with.multiple.dots.txt")
    if file_content is None:
        print("Attempt to read invalid file was correctly blocked.")

    file_content = read_safe_file("data/with/slashes.txt")
    if file_content is None:
        print("Attempt to read invalid file was correctly blocked.")

    # Example of a symbolic link (assuming it exists)
    try:
        os.symlink("/etc/passwd", "/safe/evil_link.txt") # Create a symlink for testing
        file_content = read_safe_file("evil_link.txt")
        if file_content is None:
            print("Attempt to read symbolic link was correctly blocked.")
        os.remove("/safe/evil_link.txt") # Remove the symlink
    except OSError as e:
        print(f"Could not create symbolic link for testing: {e}")

    # Clean up the test file
    try:
        os.remove("/safe/my_data.txt")
    except OSError as e:
        print(f"Error removing test file: {e}")

