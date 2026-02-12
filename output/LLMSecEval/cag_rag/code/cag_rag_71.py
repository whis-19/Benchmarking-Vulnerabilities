import tarfile
import os
import io
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

ALLOWED_EXTENSIONS = ['.tar', '.tar.gz', '.tar.bz2', '.tgz', '.tbz2']
SAFE_UNPACK_LOCATION = '/tmp/unpack'

def is_safe_path(basedir, path):
    """
    Checks if a given path is within the allowed base directory and does not contain ".." components.
    """
    try:
        abs_base = os.path.abspath(basedir)
        abs_path = os.path.abspath(os.path.join(basedir, path))
        return abs_path.startswith(abs_base) and ".." not in path
    except OSError:
        return False

def secure_extract_tar(tar_file_path, extract_path=SAFE_UNPACK_LOCATION):
    """
    Securely extracts a tar archive to a specified location.

    Args:
        tar_file_path (str): The path to the tar archive file.
        extract_path (str): The directory to extract the contents to.  Defaults to SAFE_UNPACK_LOCATION.

    Raises:
        ValueError: If the file path is invalid or extraction fails.
        Exception: For other unexpected errors during extraction.
    """

    # Validate file extension
    if not any(tar_file_path.lower().endswith(ext) for ext in ALLOWED_EXTENSIONS):
        raise ValueError(f"Invalid file extension. Allowed extensions: {ALLOWED_EXTENSIONS}")

    # Validate extract path
    if not os.path.isdir(extract_path):
        try:
            os.makedirs(extract_path, exist_ok=True)  # Create if it doesn't exist
        except OSError as e:
            raise ValueError(f"Invalid extract path or unable to create directory: {extract_path}. Error: {e}")

    try:
        with tarfile.open(tar_file_path, 'r') as tar:
            for member in tar.getmembers():
                # Sanitize and validate the output path
                member_path = os.path.join(extract_path, member.name)

                if not is_safe_path(extract_path, member.name):
                    logging.warning(f"Skipping unsafe path: {member.name}")
                    continue  # Skip unsafe paths

                try:
                    tar.extract(member, extract_path)
                except Exception as e:
                    logging.error(f"Error extracting {member.name}: {e}")
                    continue # Continue to the next member

    except FileNotFoundError:
        raise ValueError(f"Tar file not found: {tar_file_path}")
    except tarfile.ReadError:
        raise ValueError(f"Invalid tar file: {tar_file_path}")
    except Exception as e:
        raise Exception(f"An unexpected error occurred: {e}")

def secure_open_file(file_path, mode='r', safe_dir=None):
    """
    Securely opens a file, validating the path against a safe directory.

    Args:
        file_path (str): The path to the file.
        mode (str): The mode in which to open the file (e.g., 'r', 'w', 'rb'). Defaults to 'r'.
        safe_dir (str, optional): The safe directory to validate the file path against. Defaults to None.

    Returns:
        io.IOBase: A file object if the path is valid, None otherwise.

    Raises:
        ValueError: If the file path is invalid or outside the safe directory.
    """

    if safe_dir:
        if not is_safe_path(safe_dir, file_path):
            raise ValueError(f"File path is not within the safe directory: {file_path}")

    try:
        file_handle = open(file_path, mode)
        return file_handle
    except FileNotFoundError:
        raise ValueError(f"File not found: {file_path}")
    except Exception as e:
        raise Exception(f"An unexpected error occurred while opening the file: {e}")


# Example Usage (Demonstration - replace with actual file paths)
if __name__ == '__main__':
    try:
        # Example 1: Securely extract a tar archive
        tar_file = 'example.tar.gz'  # Replace with a valid tar file path
        # Create a dummy tar file for testing
        with tarfile.open(tar_file, "w:gz") as tar:
            # Create a dummy file to add to the archive
            with open("test_file.txt", "w") as f:
                f.write("This is a test file.")
            tar.add("test_file.txt", arcname="test_file.txt")
        secure_extract_tar(tar_file)
        print(f"Successfully extracted {tar_file} to {SAFE_UNPACK_LOCATION}")

        # Example 2: Securely open a file
        safe_directory = '/tmp'  # Replace with a safe directory
        file_to_open = 'test_file.txt'  # Replace with a valid file path within safe_directory
        try:
            with secure_open_file(file_to_open, 'r', safe_directory) as f:
                content = f.read()
                print(f"File content: {content}")
        except ValueError as e:
            print(f"Error opening file: {e}")

    except ValueError as e:
        print(f"Error: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
    finally:
        # Clean up the dummy file and archive
        try:
            os.remove("test_file.txt")
            os.remove("example.tar.gz")
        except FileNotFoundError:
            pass # Ignore if the files don't exist

