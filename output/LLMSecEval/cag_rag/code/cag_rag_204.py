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
    Checks if a given path is within the allowed base directory.
    Prevents path traversal vulnerabilities.
    """
    abs_base = os.path.abspath(basedir)
    abs_path = os.path.abspath(os.path.join(basedir, path))
    return abs_path.startswith(abs_base)

def secure_extract_tar(tar_file_path):
    """
    Securely extracts a tar archive to a safe location.

    Args:
        tar_file_path (str): The path to the tar archive file.

    Returns:
        bool: True if extraction was successful, False otherwise.
    """

    # Validate file extension
    if not any(tar_file_path.lower().endswith(ext) for ext in ALLOWED_EXTENSIONS):
        logging.error(f"Invalid file extension for {tar_file_path}. Allowed extensions: {ALLOWED_EXTENSIONS}")
        return False

    # Validate file path (basic check - more robust validation might be needed)
    if not os.path.isfile(tar_file_path):
        logging.error(f"Tar file not found: {tar_file_path}")
        return False

    try:
        with tarfile.open(tar_file_path, 'r') as tar:
            for member in tar.getmembers():
                # Sanitize and validate the output path
                member_path = member.name
                if ".." in member_path:
                    logging.warning(f"Skipping entry {member_path} due to potential path traversal.")
                    continue

                # Construct the full output path
                output_path = os.path.join(SAFE_UNPACK_LOCATION, member_path)

                # Check if the output path is safe
                if not is_safe_path(SAFE_UNPACK_LOCATION, member_path):
                    logging.warning(f"Skipping unsafe path: {output_path}")
                    continue

                try:
                    # Extract the member
                    tar.extract(member, SAFE_UNPACK_LOCATION)
                    logging.info(f"Extracted {member_path} to {output_path}")

                except Exception as e:
                    logging.error(f"Error extracting {member_path}: {e}")
                    return False

        return True

    except tarfile.ReadError as e:
        logging.error(f"Tarfile ReadError: {e}")
        return False
    except FileNotFoundError as e:
        logging.error(f"File Not Found Error: {e}")
        return False
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        return False

def secure_file_read(file_path):
    """
    Securely reads a file.

    Args:
        file_path (str): The path to the file.

    Returns:
        str: The content of the file, or None if an error occurred.
    """
    # Validate file path (basic check - more robust validation might be needed)
    if not os.path.isfile(file_path):
        logging.error(f"File not found: {file_path}")
        return None

    try:
        with open(file_path, 'r') as f:
            content = f.read()
        return content
    except FileNotFoundError:
        logging.error(f"File not found: {file_path}")
        return None
    except IOError as e:
        logging.error(f"IOError reading file {file_path}: {e}")
        return None
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        return None

def secure_file_write(file_path, content):
    """
    Securely writes content to a file.

    Args:
        file_path (str): The path to the file.
        content (str): The content to write.

    Returns:
        bool: True if the write was successful, False otherwise.
    """

    # Validate file path (basic check - more robust validation might be needed)
    # Example: Ensure the file is within a safe directory
    safe_dir = "/tmp/safe_writes"
    if not os.path.abspath(file_path).startswith(os.path.abspath(safe_dir)):
        logging.error(f"File path {file_path} is not within the safe directory {safe_dir}")
        return False

    try:
        # Ensure the directory exists
        os.makedirs(os.path.dirname(file_path), exist_ok=True)

        with open(file_path, 'w') as f:
            f.write(content)
        return True
    except IOError as e:
        logging.error(f"IOError writing to file {file_path}: {e}")
        return False
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        return False

if __name__ == '__main__':
    # Example usage:

    # Create a dummy tar file for testing
    test_tar_file = '/tmp/test.tar.gz'
    with tarfile.open(test_tar_file, "w:gz") as tar:
        # Create a dummy file to add to the archive
        with open("/tmp/test_file.txt", "w") as f:
            f.write("This is a test file.")
        tar.add("/tmp/test_file.txt", arcname="test_file.txt")
        os.remove("/tmp/test_file.txt")

    # Securely extract the tar file
    if secure_extract_tar(test_tar_file):
        logging.info("Tar file extracted successfully.")
    else:
        logging.error("Tar file extraction failed.")

    # Securely read a file
    file_content = secure_file_read('/tmp/unpack/test_file.txt')
    if file_content:
        logging.info(f"File content: {file_content}")
    else:
        logging.error("File read failed.")

    # Securely write to a file
    if secure_file_write('/tmp/safe_writes/output.txt', 'This is some secure content.'):
        logging.info("File written successfully.")
    else:
        logging.error("File write failed.")

    # Clean up test files and directories
    os.remove(test_tar_file)
    os.remove('/tmp/unpack/test_file.txt')
    os.rmdir('/tmp/unpack')
    os.remove('/tmp/safe_writes/output.txt')
    os.rmdir('/tmp/safe_writes')

