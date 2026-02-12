import os
import pathlib
import stat
import errno
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

SAFE_DIRECTORY = "/path/to/your/safe/directory"  # Replace with the actual safe directory path
MAX_FILE_SIZE = 1024 * 1024  # 1MB - Maximum allowed file size to prevent DoS
CHUNK_SIZE = 4096  # Read in 4KB chunks


def read_file_from_safe_directory(filename):
    """
    Reads the content of a file from the safe directory.

    Args:
        filename (str): The name of the file to read.

    Returns:
        str: The content of the file, or None if the file is not found or an error occurs.
    """
    try:
        # 1. Sanitize the filename to prevent path traversal vulnerabilities.
        sanitized_filename = os.path.basename(filename)

        # 2. Construct the full path to the file within the safe directory.
        filepath = os.path.join(SAFE_DIRECTORY, sanitized_filename)

        # 3.  Further validation: Check if the resolved path is actually within the safe directory.
        safe_path = pathlib.Path(SAFE_DIRECTORY).resolve()
        file_path_obj = pathlib.Path(filepath).resolve()

        if not file_path_obj.is_relative_to(safe_path):
            logging.warning(f"Attempted access outside safe directory: {filename}")
            print(f"Error: File '{filename}' is not within the safe directory.")
            return None

        # 4. Check if the file is a symlink.  If so, reject it.
        if file_path_obj.is_symlink():
            logging.warning(f"Attempted access to symlink: {filename}")
            print(f"Error: File '{filename}' is a symlink and is not allowed.")
            return None

        # 5.  Stat the file *before* opening it to mitigate TOCTOU and check file size.
        try:
            file_stat = os.stat(filepath)
        except OSError as e:
            logging.error(f"Error stating file '{filename}': {e}")
            print(f"Error stating file '{filename}': {e}")
            return None

        # 6. Check file size to prevent DoS.
        if file_stat.st_size > MAX_FILE_SIZE:
            logging.warning(f"File exceeds maximum allowed size: {filename}")
            print(f"Error: File '{filename}' exceeds the maximum allowed size of {MAX_FILE_SIZE} bytes.")
            return None

        # 7. Open and read the file in a safe manner, preventing symlink following.
        try:
            fd = os.open(filepath, os.O_RDONLY | os.O_NOFOLLOW)
        except OSError as e:
            if e.errno == errno.EINVAL and os.name == 'nt':
                # O_NOFOLLOW not supported on Windows, fall back to existing method
                logging.warning("O_NOFOLLOW not supported on Windows, falling back to standard open.")
                with open(filepath, 'r') as file:
                    content = file.read(MAX_FILE_SIZE)
                return content
            else:
                logging.error(f"Error opening file '{filename}': {e}")
                raise  # Re-raise the exception to be caught in the outer block

        content = ""
        total_read = 0
        with os.fdopen(fd, 'r') as file:
            while True:
                chunk = file.read(CHUNK_SIZE)
                if not chunk:
                    break
                total_read += len(chunk)
                if total_read > MAX_FILE_SIZE:
                    logging.warning(f"File exceeded maximum size during read: {filename}")
                    print(f"Error: File '{filename}' exceeded maximum size during read.")
                    return None  # Or truncate, depending on requirements
                content += chunk

        return content

    except FileNotFoundError:
        logging.warning(f"File not found: {filename}")
        print(f"Error: File '{filename}' not found in the safe directory.")
        return None
    except PermissionError:
        logging.warning(f"Permission denied to read file: {filename}")
        print(f"Error: Permission denied to read file '{filename}'.")
        return None
    except OSError as e:  # Catch OSError specifically for file-related errors
        logging.error(f"OS Error occurred while processing file '{filename}': {e}")
        print(f"An OS error occurred: {e}")
        return None
    except Exception as e:  # Catch any other exceptions
        logging.exception(f"An unexpected error occurred while processing file '{filename}': {e}") # Log the full exception traceback
        print(f"An unexpected error occurred: {e}")
        return None


# Example usage:
if __name__ == "__main__":
    # Replace 'my_file.txt' with the actual filename you want to read.
    file_content = read_file_from_safe_directory("my_file.txt")

    if file_content:
        print("File content:")
        print(file_content)
    else:
        print("Failed to read the file.")

    # Example of trying to access a file outside the safe directory (will fail):
    file_content = read_file_from_safe_directory("../../../etc/passwd") # Attempted path traversal
    if file_content:
        print("File content:")
        print(file_content)
    else:
        print("Failed to read the file (as expected).")

    # Example of trying to access a file with an absolute path (will fail):
    file_content = read_file_from_safe_directory("/etc/passwd") # Attempted absolute path
    if file_content:
        print("File content:")
        print(file_content)
    else:
        print("Failed to read the file (as expected).")

    # Example of trying to access a symlink (will fail):
    # Create a symlink for testing (only works if you have permissions)
    try:
        os.symlink("my_file.txt", "my_symlink.txt")
        file_content = read_file_from_safe_directory("my_symlink.txt")
        if file_content:
            print("File content (symlink):")
            print(file_content)
        else:
            print("Failed to read the file (symlink - as expected).")
        os.remove("my_symlink.txt") # Clean up the symlink
    except OSError as e:
        print(f"Could not create symlink for testing: {e}")

