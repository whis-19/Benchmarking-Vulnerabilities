import tarfile
import os
import shutil
import tempfile
import logging
import errno  # Import the errno module

# Configure logging for security-related events
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def create_destination_directory_atomic(destination_dir):
    """Atomically creates the destination directory with secure permissions."""
    try:
        os.makedirs(destination_dir, exist_ok=True, mode=0o700)
    except OSError as e:
        logging.error(f"Error creating destination directory: {e}")
        raise

def check_disk_space(destination_dir, expected_size):
    """Checks if there is enough disk space before extraction."""
    total, used, free = shutil.disk_usage(destination_dir)
    if free < expected_size:
        raise OSError(errno.ENOSPC, f"Not enough free space on device: {free} bytes available, {expected_size} bytes needed.")


def secure_extract_tarfile(tar_file_path, destination_dir="/tmp/unpack", max_extracted_size=1024 * 1024 * 100, max_files=1000, max_filename_length=255):
    """
    Securely extracts a tar archive to a specified destination directory.

    This function implements several security measures to prevent common vulnerabilities
    associated with tar archive extraction, such as path traversal and denial-of-service.

    Args:
        tar_file_path (str): The path to the tar archive file.
        destination_dir (str): The directory to extract the contents to. Defaults to "/tmp/unpack".
        max_extracted_size (int): Maximum total size of extracted files in bytes. Defaults to 100MB.
        max_files (int): Maximum number of files to extract. Defaults to 1000.
        max_filename_length (int): Maximum length of a filename. Defaults to 255.

    Raises:
        ValueError: If the tar_file_path is not a valid file.
        OSError: If there are issues creating or accessing directories, or insufficient disk space.
        tarfile.ReadError: If the tar file is invalid or corrupted.
        Exception: For other unexpected errors during extraction.
    """

    # 1. Input Validation: Check if the tar file exists
    if not os.path.isfile(tar_file_path):
        raise ValueError(f"Error: Tar file not found at {tar_file_path}")

    # 2. Create Destination Directory (with secure permissions)
    try:
        create_destination_directory_atomic(destination_dir)
    except OSError as e:
        logging.error(f"Error creating destination directory: {e}")
        raise

    # 3. Check Disk Space
    try:
        # Get the size of the tar file as an estimate for disk space needed.  A more accurate
        # estimate would require parsing the tar file headers, but this is a reasonable starting point.
        tar_file_size = os.path.getsize(tar_file_path)
        check_disk_space(destination_dir, tar_file_size)
    except OSError as e:
        logging.error(f"Error checking disk space: {e}")
        raise

    # 4. Path Traversal Prevention:  Sanitize filenames during extraction
    def is_within_directory(directory, target):
        """Checks if a target path is within a directory."""
        abs_directory = os.path.abspath(directory)
        abs_target = os.path.abspath(target)
        return abs_target.startswith(abs_directory)

    def safe_extract(tar, path=".", members=None, *, numeric_owner=False):
        """Securely extracts a tarfile, preventing path traversal vulnerabilities."""
        extracted_size = 0
        extracted_files = 0
        for member in tar.getmembers():
            member_path = os.path.join(path, member.name)
            if not is_within_directory(path, member_path):
                logging.warning(f"Attempted path traversal: {member.name}. Skipping.")
                continue  # Skip extraction of this member

            # Check for hard links and symlinks
            if member.issym() or member.ishardlink():
                logging.warning(f"Skipping symbolic or hard link: {member.name}")
                continue

            # Check filename length
            if len(member.name) > max_filename_length:
                logging.warning(f"Filename too long: {member.name}. Skipping.")
                continue

            # Resource Limits
            extracted_size += member.size
            if extracted_size > max_extracted_size:
                logging.error(f"Exceeded maximum extracted size. Aborting extraction.")
                raise Exception("Exceeded maximum extracted size")

            extracted_files += 1
            if extracted_files > max_files:
                logging.error(f"Exceeded maximum number of files. Aborting extraction.")
                raise Exception("Exceeded maximum number of files")

            try:
                tar.extract(member, path, members=members, numeric_owner=numeric_owner)
            except Exception as e:
                logging.error(f"Error extracting {member.name}: {e}")
                raise


    # 5. Extraction within a 'with' statement for proper resource management
    try:
        with tarfile.open(tar_file_path, "r:*", errorlevel=1) as tar:  # 'r:*' handles various compression types
            safe_extract(tar, destination_dir, numeric_owner=True)

    except tarfile.ReadError as e:
        logging.error(f"Error reading tar file: {e}")
        raise
    except Exception as e:
        logging.error(f"Unexpected error during extraction: {e}")
        raise

    # 6. Post-Extraction Permissions (Important!)
    # After extraction, explicitly set permissions on all extracted files and directories
    # to ensure they are not overly permissive.  This is crucial for security.
    for root, dirs, files in os.walk(destination_dir):
        for d in dirs:
            dir_path = os.path.join(root, d)
            try:
                os.chmod(dir_path, 0o700)  # Owner-only permissions for directories
            except OSError as e:
                logging.error(f"Error setting permissions for directory {dir_path}: {e}")
                # Consider whether to continue or abort here.  Aborting might be safer.
        for f in files:
            file_path = os.path.join(root, f)
            try:
                os.chmod(file_path, 0o600)  # Owner-only read/write for files
            except OSError as e:
                logging.error(f"Error setting permissions for file {file_path}: {e}")
                # Consider whether to continue or abort here.  Aborting might be safer.


    logging.info(f"Successfully extracted {tar_file_path} to {destination_dir}")


# Example Usage (with error handling):
if __name__ == "__main__":
    # Create a dummy tar file for testing (replace with your actual file)
    try:
        # Create a temporary directory
        with tempfile.TemporaryDirectory() as temp_dir:
            test_file_path = os.path.join(temp_dir, "test.txt")
            with open(test_file_path, "w") as f:
                f.write("This is a test file.")

            tar_file_path = os.path.join(temp_dir, "test.tar.gz")
            with tarfile.open(tar_file_path, "w:gz") as tar:
                tar.add(test_file_path, arcname="test.txt")  # arcname avoids full path in archive

            # Call the secure extraction function
            try:
                secure_extract_tarfile(tar_file_path)
                print("Extraction successful.")
            except (ValueError, OSError, tarfile.ReadError) as e:
                print(f"Extraction failed: {e}")
            except Exception as e:
                print(f"An unexpected error occurred: {e}")

    except Exception as e:
        print(f"Error creating test environment: {e}")

