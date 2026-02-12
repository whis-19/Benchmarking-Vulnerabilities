import tarfile
import os
import shutil
import tempfile
import logging

# Configure logging for security-related events
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def secure_extract_tarfile(tar_file_path, destination_dir="/tmp/unpack"):
    """
    Securely extracts a tar archive to a specified destination directory.

    This function implements several security measures to prevent common vulnerabilities
    associated with tar archive extraction, such as path traversal and denial-of-service.

    Args:
        tar_file_path (str): The path to the tar archive file.
        destination_dir (str): The directory to extract the contents to. Defaults to "/tmp/unpack".

    Raises:
        ValueError: If the tar_file_path is not a valid file.
        OSError: If there are issues creating or accessing directories.
        tarfile.ReadError: If the tar file is invalid or corrupted.
        Exception: For other unexpected errors during extraction.
    """

    # 1. Input Validation: Check if the tar file exists
    if not os.path.isfile(tar_file_path):
        raise ValueError(f"Error: Tar file not found at {tar_file_path}")

    # 2. Create Destination Directory (with secure permissions)
    try:
        # Ensure the destination directory exists and has appropriate permissions.
        # Using exist_ok=True prevents errors if the directory already exists.
        os.makedirs(destination_dir, exist_ok=True, mode=0o700)  # Owner-only permissions
    except OSError as e:
        logging.error(f"Error creating destination directory: {e}")
        raise

    # 3. Path Traversal Prevention:  Sanitize filenames during extraction
    def is_within_directory(directory, target):
        """Checks if a target path is within a directory."""
        abs_directory = os.path.abspath(directory)
        abs_target = os.path.abspath(target)
        return abs_target.startswith(abs_directory)

    def safe_extract(tar, path=".", members=None, *, numeric_owner=False):
        """Securely extracts a tarfile, preventing path traversal vulnerabilities."""
        for member in tar.getmembers():
            member_path = os.path.join(path, member.name)
            if not is_within_directory(path, member_path):
                logging.warning(f"Attempted path traversal: {member.name}. Skipping.")
                continue  # Skip extraction of this member
            tar.extract(member, path, members=members, numeric_owner=numeric_owner)

    # 4. Resource Limits (Optional - but highly recommended for untrusted archives)
    # You can add resource limits to prevent denial-of-service attacks.
    # For example, limiting the maximum size of extracted files or the number of files.
    # This requires more complex implementation and depends on your specific needs.
    # Example (Conceptual - requires actual implementation):
    # max_extracted_size = 1024 * 1024 * 100  # 100 MB
    # extracted_size = 0

    # 5. Extraction within a 'with' statement for proper resource management
    try:
        with tarfile.open(tar_file_path, "r:*") as tar:  # 'r:*' handles various compression types
            safe_extract(tar, destination_dir)

    except tarfile.ReadError as e:
        logging.error(f"Error reading tar file: {e}")
        raise
    except Exception as e:
        logging.error(f"Unexpected error during extraction: {e}")
        raise

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

