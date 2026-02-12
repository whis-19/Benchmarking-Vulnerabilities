import tarfile
import os
import io
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

ALLOWED_EXTENSIONS = ['.tar', '.tar.gz', '.tar.bz2']
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
    if not any(tar_file_path.lower().endswith(ext) for ext in ALLOWED_EXTENSIONS):
        logging.error(f"Invalid file extension for {tar_file_path}. Allowed extensions: {ALLOWED_EXTENSIONS}")
        raise ValueError(f"Invalid file extension. Allowed extensions: {ALLOWED_EXTENSIONS}")

    # Validate file path (basic check - more robust validation might be needed)
    if not os.path.isfile(tar_file_path):
        logging.error(f"Tar file not found: {tar_file_path}")
        raise FileNotFoundError(f"Tar file not found: {tar_file_path}")

    try:
        with tarfile.open(tar_file_path, 'r') as tar:
            for member in tar.getmembers():
                # Construct the full path to the extracted file
                member_path = os.path.join(SAFE_UNPACK_DIR, member.name)

                # Validate the output path to prevent path traversal
                if not is_safe_path(SAFE_UNPACK_DIR, member.name):
                    logging.warning(f"Attempted path traversal detected: {member.name}. Skipping extraction.")
                    continue  # Skip this member

                # Ensure the directory exists before extracting
                member_dir = os.path.dirname(member_path)
                if not os.path.exists(member_dir):
                    try:
                        os.makedirs(member_dir, exist_ok=True)
                    except OSError as e:
                        logging.error(f"Failed to create directory {member_dir}: {e}")
                        continue

                try:
                    tar.extract(member, path=SAFE_UNPACK_DIR)
                    logging.info(f"Extracted {member.name} to {member_path}")
                except Exception as e:
                    logging.error(f"Failed to extract {member.name}: {e}")

    except tarfile.ReadError as e:
        logging.error(f"Tarfile ReadError: {e}")
        raise
    except FileNotFoundError as e:
        logging.error(f"File Not Found Error: {e}")
        raise
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        raise

def secure_file_read(file_path):
    """
    Securely reads a file, ensuring it's closed properly.

    Args:
        file_path (str): The path to the file.

    Returns:
        str: The content of the file, or None if an error occurred.
    """
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
        logging.error(f"An unexpected error occurred while reading {file_path}: {e}")
        return None

def validate_filepath(filepath):
    """
    Validates a filepath to prevent path traversal and other security issues.
    """
    if not isinstance(filepath, str):
        raise TypeError("Filepath must be a string.")

    if any(sep in filepath for sep in ["/", "\\"]):
        raise ValueError("Filepath cannot contain directory separators.")

    if ".." in filepath:
        raise ValueError("Filepath cannot contain '..' sequences.")

    if not filepath:
        raise ValueError("Filepath cannot be empty.")

    # Add more validation as needed, e.g., length limits, character restrictions

    return filepath

# Example usage:
if __name__ == '__main__':
    # Create a dummy tar file for testing
    test_tar_file = '/tmp/test.tar.gz'
    if not os.path.exists(test_tar_file):
        try:
            with tarfile.open(test_tar_file, "w:gz") as tar:
                # Create a dummy file to add to the archive
                dummy_file_path = "/tmp/dummy_file.txt"
                with open(dummy_file_path, "w") as f:
                    f.write("This is a test file.")
                tarinfo = tarfile.TarInfo("dummy_file.txt")
                tarinfo.size = os.path.getsize(dummy_file_path)
                with open(dummy_file_path, "rb") as f:
                    tar.addfile(tarinfo, f)
                os.remove(dummy_file_path)
        except Exception as e:
            print(f"Error creating test tar file: {e}")
            exit(1)

    try:
        secure_extract_tar(test_tar_file)
        print(f"Successfully extracted {test_tar_file} to {SAFE_UNPACK_DIR}")
    except Exception as e:
        print(f"Extraction failed: {e}")

    # Example of secure file reading
    try:
        file_content = secure_file_read('/tmp/unpack/dummy_file.txt')
        if file_content:
            print(f"File content: {file_content}")
    except Exception as e:
        print(f"Error reading file: {e}")

    # Example of filepath validation
    try:
        validated_path = validate_filepath("myfile.txt")
        print(f"Validated path: {validated_path}")
    except ValueError as e:
        print(f"Filepath validation error: {e}")

    try:
        validated_path = validate_filepath("../myfile.txt")  # This will raise an error
        print(f"Validated path: {validated_path}")
    except ValueError as e:
        print(f"Filepath validation error: {e}")

