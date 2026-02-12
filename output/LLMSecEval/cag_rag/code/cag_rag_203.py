import zipfile
import os
import stat
import logging

logging.basicConfig(level=logging.INFO)

def secure_extract_zip(zip_file_path, extract_dir):
    """
    Securely extracts a zip file to a specified directory.

    Args:
        zip_file_path (str): The path to the zip file.
        extract_dir (str): The directory to extract the contents to.
    """

    # Validate file paths
    if not is_safe_path(zip_file_path):
        raise ValueError("Unsafe zip file path.")
    if not is_safe_path(extract_dir):
        raise ValueError("Unsafe extract directory path.")

    # Create extract directory if it doesn't exist
    try:
        os.makedirs(extract_dir, exist_ok=True)
    except OSError as e:
        logging.error(f"Failed to create directory {extract_dir}: {e}")
        raise

    try:
        with zipfile.ZipFile(zip_file_path, 'r') as zip_ref:
            for member in zip_ref.infolist():
                # Sanitize file name to prevent path traversal
                file_path = os.path.join(extract_dir, member.filename)
                file_path = os.path.normpath(file_path)

                if not file_path.startswith(os.path.abspath(extract_dir)):
                    logging.warning(f"Skipping potentially unsafe path: {member.filename}")
                    continue

                # Check for directory traversal attempts
                if ".." in member.filename:
                    logging.warning(f"Skipping entry with directory traversal: {member.filename}")
                    continue

                # Extract the file
                try:
                    zip_ref.extract(member, extract_dir)
                    # Set permissions (example: read/write for owner, read for group/others)
                    os.chmod(file_path, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH)
                except Exception as e:
                    logging.error(f"Failed to extract {member.filename}: {e}")
                    continue

    except zipfile.BadZipFile:
        logging.error(f"Invalid zip file: {zip_file_path}")
        raise
    except FileNotFoundError:
        logging.error(f"Zip file not found: {zip_file_path}")
        raise
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        raise


def is_safe_path(file_path, safe_base_path="/tmp"):
    """
    Checks if a file path is safe, preventing directory traversal attacks.
    """
    if not isinstance(file_path, str):
        return False

    if ".." in file_path:
        return False

    if "/" in file_path or "\\" in file_path:
        return False

    if file_path.count(".") > 1:
        return False

    abs_path = os.path.abspath(file_path)
    abs_base_path = os.path.abspath(safe_base_path)

    return abs_path.startswith(abs_base_path)


if __name__ == '__main__':
    # Example usage:
    zip_file = 'archive.zip'  # Replace with your zip file
    extract_location = '/tmp/unpack'

    # Create a dummy zip file for testing
    if not os.path.exists(zip_file):
        with zipfile.ZipFile(zip_file, 'w') as zf:
            zf.writestr("test.txt", "This is a test file.")
            zf.writestr("safe_dir/test2.txt", "This is another test file.")

    try:
        secure_extract_zip(zip_file, extract_location)
        print(f"Successfully extracted {zip_file} to {extract_location}")
    except ValueError as e:
        print(f"Error: {e}")
    except Exception as e:
        print(f"An error occurred: {e}")

