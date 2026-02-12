import zipfile
import os
import stat
import io
import tempfile
import shutil
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

ALLOWED_EXTRACT_PATHS = ["/tmp"]  # Example allowed paths


def secure_extract_zip(zip_file_path, extract_path=None, max_extracted_size=1024 * 1024 * 100, max_compression_ratio=1000, max_files=1000):  # 100MB default, 1000 ratio, 1000 files
    """
    Securely extracts a zip file to a specified directory.

    Args:
        zip_file_path (str): The path to the zip file.
        extract_path (str, optional): The directory to extract the contents to.
                                      If None, a temporary directory is created.
        max_extracted_size (int, optional): Maximum total size of extracted files in bytes.
                                            Defaults to 100MB.
        max_compression_ratio (int, optional): Maximum allowed compression ratio (uncompressed size / compressed size).
                                               Defaults to 1000.
        max_files (int, optional): Maximum number of files allowed in the archive. Defaults to 1000.
    """

    # Create a temporary directory if extract_path is not provided.
    if extract_path is None:
        extract_path = tempfile.mkdtemp(prefix="zip_extract_")
        cleanup_required = True
        logging.info(f"Created temporary extraction directory: {extract_path}")
    else:
        if not any(extract_path.startswith(allowed_path) for allowed_path in ALLOWED_EXTRACT_PATHS):
            raise ValueError(f"Extract path must be within one of the allowed directories: {ALLOWED_EXTRACT_PATHS}")
        cleanup_required = False
        logging.info(f"Using provided extraction directory: {extract_path}")

    # Create the extraction directory if it doesn't exist.
    try:
        os.makedirs(extract_path, exist_ok=True)
    except OSError as e:
        logging.error(f"Failed to create extraction directory: {e}")
        raise Exception(f"Failed to create extraction directory: {e}")

    total_extracted_size = 0
    num_files_extracted = 0

    # Set umask to 0 to ensure consistent permissions
    old_umask = os.umask(0)
    try:
        with zipfile.ZipFile(zip_file_path, 'r', encoding='utf-8') as zip_ref:
            for member in zip_ref.infolist():
                # Secure path validation:  Prevent directory traversal attacks.
                # Normalize the path and check for ".."
                filepath = os.path.normpath(os.path.join(extract_path, member.filename))
                if not filepath.startswith(extract_path):
                    logging.warning(f"Path traversal attempt detected: {member.filename}")
                    raise ValueError(f"Invalid zip file: Path traversal attempt detected: {member.filename}")

                # Secure path validation:  Check for absolute paths.
                if os.path.isabs(filepath):
                    logging.warning(f"Absolute path detected: {member.filename}")
                    raise ValueError(f"Invalid zip file: Absolute path detected: {member.filename}")

                # Check for symbolic links
                if stat.S_ISLNK(member.external_attr >> 16):
                    logging.warning(f"Symbolic link detected: {member.filename}. Skipping extraction.")
                    continue

                # Check if file already exists to prevent overwrites
                if os.path.exists(filepath):
                    logging.warning(f"File already exists: {filepath}. Skipping extraction.")
                    continue

                # Check for zip bombs (size limits)
                if not member.is_dir():
                    extracted_size = member.file_size  # Uncompressed size
                    if extracted_size + total_extracted_size > max_extracted_size:
                        logging.warning(f"Zip bomb detected: Exceeds maximum extracted size.  File: {member.filename}, Size: {extracted_size}")
                        raise ValueError("Zip bomb detected: Exceeds maximum extracted size.")

                    compression_ratio = extracted_size / member.compress_size if member.compress_size > 0 else float('inf')
                    if compression_ratio > max_compression_ratio:
                        logging.warning(f"Zip bomb detected: Excessive compression ratio. File: {member.filename}, Ratio: {compression_ratio}")
                        raise ValueError("Zip bomb detected: Excessive compression ratio.")

                # Extract the file.  Use extract() instead of extractall() for better control.
                try:
                    zip_ref.extract(member, extract_path)
                    if not member.is_dir():
                        total_extracted_size += extracted_size
                    logging.debug(f"Extracted {member.filename} to {filepath}")
                except Exception as e:
                    logging.error(f"Error extracting {member.filename}: {e}")
                    # Consider logging the error and potentially halting the process
                    # depending on the criticality of the file.
                    continue  # Or raise the exception if extraction is critical.

                # Apply consistent permissions.
                try:
                    filepath_stat = os.stat(filepath)
                    if stat.S_ISDIR(filepath_stat.st_mode):
                        os.chmod(filepath, 0o755)  # Directory permissions
                    else:
                        os.chmod(filepath, 0o644)  # File permissions
                    logging.debug(f"Set permissions for {member.filename} to {oct(os.stat(filepath).st_mode & 0o777)}")
                except OSError as e:
                    logging.error(f"Error setting permissions for {member.filename}: {e}")

                num_files_extracted += 1
                if num_files_extracted > max_files:
                    logging.warning("Too many files in zip archive.  Possible resource exhaustion attempt.")
                    raise ValueError("Too many files in zip archive.")


    except zipfile.BadZipFile:
        logging.error("Invalid zip file.")
        raise ValueError("Invalid zip file.")
    except Exception as e:
        logging.error(f"An error occurred during zip extraction: {e}")
        raise Exception(f"An error occurred during zip extraction: {e}")
    finally:
        os.umask(old_umask)  # Restore original umask
        if cleanup_required:
            try:
                shutil.rmtree(extract_path)
                logging.info(f"Cleaned up temporary directory: {extract_path}")
            except OSError as e:
                logging.error(f"Error cleaning up temporary directory {extract_path}: {e}")
                # Consider logging this error.


# Example usage:
if __name__ == '__main__':
    # Create a dummy zip file for testing.  Important:  Never use untrusted zip files
    # in a production environment without thorough validation and sanitization.
    def create_test_zip(zip_file_path, include_evil=False):
        with zipfile.ZipFile(zip_file_path, 'w') as zip_file:
            zip_file.writestr("test.txt", "This is a test file.")
            zip_file.writestr("subdir/test2.txt", "This is another test file.")
            if include_evil:
                # Attempted path traversal (should be blocked)
                zip_file.writestr("../../../evil.txt", "This should not be extracted.")
                # Absolute path (should be blocked)
                zip_file.writestr("/tmp/absolute.txt", "This should not be extracted.")
                # Zip bomb
                zip_file.writestr("large_file.txt", "A" * 1024 * 1024 * 500) # 500MB file
                # Symbolic link
                if os.name != 'nt':  # Symbolic links are different on Windows
                    try:
                        os.symlink("test.txt", "link_to_test.txt")
                        zip_file.write("link_to_test.txt")
                        os.remove("link_to_test.txt")
                    except OSError as e:
                        print(f"Could not create symbolic link for testing: {e}")


    test_zip_file = "/tmp/test_archive.zip"
    extract_dir = None  # Use a temporary directory

    create_test_zip(test_zip_file, include_evil=True)

    try:
        secure_extract_zip(test_zip_file, extract_dir, max_extracted_size=1024 * 1024 * 10) # Limit to 10MB
        print(f"Successfully extracted {test_zip_file} to {extract_dir}")
    except ValueError as e:
        print(f"Error: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

    # Clean up the test zip file (optional).
    try:
        os.remove(test_zip_file)
    except OSError as e:
        print(f"Error removing test zip file: {e}")

