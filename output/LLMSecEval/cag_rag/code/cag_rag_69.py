import zipfile
import os
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def secure_extract_zip(zip_file_path, extract_path):
    """
    Securely extracts a zip file to a specified directory.

    Args:
        zip_file_path (str): The path to the zip file.
        extract_path (str): The directory to extract the contents to.
    """

    # Validate file paths
    if not is_safe_path(zip_file_path):
        raise ValueError("Unsafe zip file path.")
    if not is_safe_path(extract_path):
        raise ValueError("Unsafe extract path.")

    # Create the extraction directory if it doesn't exist
    try:
        os.makedirs(extract_path, exist_ok=True)
    except OSError as e:
        logging.error(f"Failed to create extraction directory: {e}")
        raise

    try:
        with zipfile.ZipFile(zip_file_path, 'r') as zip_ref:
            for member in zip_ref.infolist():
                # Sanitize the file name
                file_path = os.path.join(extract_path, member.filename)
                
                if not is_safe_extraction_path(extract_path, file_path):
                    logging.warning(f"Skipping unsafe path: {file_path}")
                    continue

                try:
                    zip_ref.extract(member, extract_path)
                except Exception as e:
                    logging.error(f"Failed to extract {member.filename}: {e}")
                    continue

                # Secure file permissions (example: read/write for owner only)
                try:
                    os.chmod(file_path, 0o600)
                except OSError as e:
                    logging.warning(f"Failed to set permissions for {file_path}: {e}")

    except zipfile.BadZipFile:
        logging.error(f"Invalid zip file: {zip_file_path}")
        raise
    except FileNotFoundError:
        logging.error(f"Zip file not found: {zip_file_path}")
        raise
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        raise

def is_safe_path(file_path):
    """
    Checks if a file path is safe.  This implementation checks for:
    - Absolute paths
    - ".." sequences (path traversal)
    - Directory separators in the filename
    - Multiple "." characters in the filename

    Args:
        file_path (str): The file path to check.

    Returns:
        bool: True if the path is safe, False otherwise.
    """
    if os.path.isabs(file_path):
        logging.warning(f"Path is absolute: {file_path}")
        return False

    normalized_path = os.path.normpath(file_path)
    if ".." in normalized_path:
        logging.warning(f"Path contains '..': {file_path}")
        return False

    if os.path.basename(file_path) != file_path:
        logging.warning(f"Path contains directory separators: {file_path}")
        return False

    if os.path.basename(file_path).count(".") > 1:
        logging.warning(f"Path contains multiple '.' characters: {file_path}")
        return False

    return True

def is_safe_extraction_path(extract_path, file_path):
    """
    Verifies that the extracted file path is within the intended extraction directory
    and does not contain path traversal vulnerabilities.

    Args:
        extract_path (str): The base extraction directory.
        file_path (str): The full path to the file being extracted.

    Returns:
        bool: True if the extraction path is safe, False otherwise.
    """
    try:
        # Resolve both paths to their absolute, canonical forms
        abs_extract_path = os.path.abspath(extract_path)
        abs_file_path = os.path.abspath(file_path)

        # Check if the file path starts with the extract path
        if not abs_file_path.startswith(abs_extract_path):
            logging.warning(f"Extraction path is outside the base directory: {file_path}")
            return False

        # Further check to prevent traversal using '..'
        rel_path = os.path.relpath(abs_file_path, abs_extract_path)
        if rel_path.startswith('..') or os.path.isabs(rel_path):
            logging.warning(f"Path traversal detected: {file_path}")
            return False

        return True

    except ValueError:
        logging.error(f"Invalid path encountered during safety check.")
        return False
    except Exception as e:
        logging.error(f"An error occurred during path safety check: {e}")
        return False


if __name__ == '__main__':
    # Example usage:
    zip_file = 'archive.zip'  # Replace with the actual path to your zip file
    extract_dir = '/tmp/unpack'  # Replace with your desired extraction directory

    # Create a dummy zip file for testing
    if not os.path.exists(zip_file):
        with zipfile.ZipFile(zip_file, 'w') as zf:
            zf.writestr("test_file.txt", "This is a test file.")
            zf.writestr("subdir/another_file.txt", "This is another test file.")

    try:
        secure_extract_zip(zip_file, extract_dir)
        print(f"Successfully extracted '{zip_file}' to '{extract_dir}'")
    except ValueError as e:
        print(f"Error: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

