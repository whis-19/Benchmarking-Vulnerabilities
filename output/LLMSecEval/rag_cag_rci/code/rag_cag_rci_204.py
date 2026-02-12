import tarfile
import os
import io
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

ALLOWED_EXTENSIONS = ['.tar', '.tar.gz', '.tar.bz2', '.tgz', '.tbz2']
SAFE_UNPACK_DIR = '/tmp/unpack'

def is_safe_path(basedir, path):
    """
    Checks if a given path is within the allowed base directory and does not contain path traversal vulnerabilities.
    """
    abs_basedir = os.path.abspath(basedir)
    abs_path = os.path.abspath(os.path.join(basedir, path))
    return abs_path.startswith(abs_basedir)

def secure_extract_tar(tar_file_path):
    """
    Securely extracts a tar archive to a safe directory.

    Args:
        tar_file_path (str): The path to the tar archive file.
    """

    # Validate file extension
    if not tar_file_path.lower().endswith(tuple(ALLOWED_EXTENSIONS)):
        logging.error(f"Invalid file extension: {tar_file_path}. Allowed extensions: {ALLOWED_EXTENSIONS}")
        raise ValueError("Invalid file extension. Allowed extensions: {}".format(ALLOWED_EXTENSIONS))

    # Validate file path (basic check - more robust validation might be needed)
    if not os.path.isfile(tar_file_path):
        logging.error(f"File not found: {tar_file_path}")
        raise FileNotFoundError(f"File not found: {tar_file_path}")

    try:
        with tarfile.open(tar_file_path, 'r') as tar:
            for member in tar.getmembers():
                # Construct the full path to the extracted file
                member_path = os.path.join(SAFE_UNPACK_DIR, member.name)

                # Validate the output path to prevent path traversal
                if not is_safe_path(SAFE_UNPACK_DIR, member.name):
                    logging.warning(f"Path traversal attempt detected: {member.name}. Skipping extraction.")
                    continue  # Skip this member

                # Ensure the directory exists before extracting
                member_dir = os.path.dirname(member_path)
                if not os.path.exists(member_dir):
                    try:
                        os.makedirs(member_dir, exist_ok=True)  # Create directory if it doesn't exist
                    except OSError as e:
                        logging.error(f"Failed to create directory {member_dir}: {e}")
                        continue # Skip this member

                try:
                    tar.extract(member, path=SAFE_UNPACK_DIR)
                    logging.info(f"Extracted {member.name} to {member_path}")
                except Exception as e:
                    logging.error(f"Failed to extract {member.name}: {e}")

    except tarfile.ReadError as e:
        logging.error(f"Tarfile read error: {e}")
        raise
    except FileNotFoundError as e:
        logging.error(f"File not found: {e}")
        raise
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        raise

def secure_open_file(file_path, mode='r', encoding=None):
    """
    Securely opens a file, validating the path and ensuring it's closed.

    Args:
        file_path (str): The path to the file.
        mode (str): The mode in which to open the file (e.g., 'r', 'w', 'rb').
        encoding (str, optional): The encoding to use when opening the file in text mode. Defaults to None.

    Returns:
        io.IOBase: A file object.

    Raises:
        ValueError: If the file path is invalid.
        FileNotFoundError: If the file does not exist.
        Exception: For other errors during file opening.
    """

    # Validate file path (example: check for directory separators and ".." sequences)
    if "/" in file_path or "\\" in file_path or ".." in file_path:
        logging.error(f"Invalid file path: {file_path}.  Path contains directory separators or '..' sequences.")
        raise ValueError("Invalid file path. Path contains directory separators or '..' sequences.")

    # Check if the file is within a safe directory (example)
    safe_dir = "/tmp/safe_files"  # Define a safe directory
    if not is_safe_path(safe_dir, file_path):
        logging.error(f"File path is not within the safe directory: {file_path}")
        raise ValueError("File path is not within the safe directory.")

    try:
        if 'b' in mode:
            file_handle = open(file_path, mode)
        else:
            file_handle = open(file_path, mode, encoding=encoding)
        return file_handle
    except FileNotFoundError as e:
        logging.error(f"File not found: {e}")
        raise
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        raise

def example_usage():
    """
    Example usage of the secure functions.
    """
    # Example: Securely extract a tar archive
    try:
        # Create a dummy tar file for testing (replace with your actual tar file)
        # Note:  Creating a tar file programmatically is complex and beyond the scope of this example.
        #        You should have a pre-existing tar file for testing.
        #        For example:  `tar -czvf test.tar.gz some_directory`
        dummy_tar_file = "test.tar.gz"  # Replace with your tar file path
        if not os.path.exists(dummy_tar_file):
            print(f"Please create a tar file named {dummy_tar_file} for testing.")
            return

        secure_extract_tar(dummy_tar_file)
        print(f"Successfully extracted {dummy_tar_file} to {SAFE_UNPACK_DIR}")

    except Exception as e:
        print(f"Error during tar extraction: {e}")

    # Example: Securely open a file
    try:
        safe_file_path = os.path.join("/tmp/safe_files", "my_file.txt")
        os.makedirs("/tmp/safe_files", exist_ok=True)
        with open(safe_file_path, "w") as f:
            f.write("This is a test file.")

        with secure_open_file(safe_file_path, 'r', encoding='utf-8') as f:
            content = f.read()
            print(f"File content: {content}")

    except Exception as e:
        print(f"Error during file opening: {e}")

if __name__ == "__main__":
    example_usage()

