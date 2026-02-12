import tarfile
import os
import logging
import pwd
import grp
import hashlib

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

ALLOWED_EXTENSIONS = ['.txt']  # More restrictive default
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB limit

def is_safe_path(base, path):
    """
    Checks if a path is safe to extract to, preventing path traversal vulnerabilities.
    """
    try:
        safe_path = os.path.abspath(os.path.normpath(os.path.join(base, path)))
        base = os.path.abspath(os.path.normpath(base))
        return safe_path.startswith(base + os.sep)
    except ValueError:
        return False

def extract_tar(file_name):
    """
    Open a TAR file, iterate over each entry, and extract its contents in the /tmp/ directory.
    """
    try:
        file_name = os.path.abspath(file_name)

        if not (file_name.lower().endswith('.tar.gz') or file_name.lower().endswith('.tar')):
            raise ValueError("Only .tar and .tar.gz files are allowed.")


        # Calculate SHA256 hash for integrity check (example - replace with actual hash)
        # expected_hash = "your_expected_sha256_hash_here"
        # actual_hash = calculate_sha256(file_name)
        # if actual_hash != expected_hash:
        #     logging.error(f"TAR file integrity check failed. Expected: {expected_hash}, Actual: {actual_hash}")
        #     raise ValueError("TAR file integrity check failed.")


        with tarfile.open(file_name, 'r:*') as tar: # Added support for compressed tar files
            # Get the UID and GID of a non-privileged user (e.g., 'nobody')
            try:
                nobody_uid = pwd.getpwnam("nobody").pw_uid
                nobody_gid = grp.getgrnam("nogroup").gr_gid
            except KeyError:
                logging.warning("User 'nobody' or group 'nogroup' not found.  Using current user/group.")
                nobody_uid = os.getuid()
                nobody_gid = os.getgid()

            extracted_file_count = 0
            max_files_to_extract = 100  # Example limit

            total_extracted_size = 0
            max_total_extracted_size = 100 * 1024 * 1024 # 100MB limit

            for member in tar.getmembers():
                # Validate filename against allowlist (example)
                if not any(member.name.lower().endswith(ext) for ext in ALLOWED_EXTENSIONS):
                    logging.warning(f"Skipping {member.name} due to disallowed extension.")
                    continue

                # Construct the full extraction path
                extract_path = os.path.join('/tmp', member.name)

                # Check for path traversal vulnerabilities
                if not is_safe_path('/tmp', member.name):
                    logging.warning(f"Skipping {member.name} due to potential path traversal.")
                    continue

                # Check file size before extraction (example)
                if member.size > MAX_FILE_SIZE:
                    logging.warning(f"Skipping {member.name} due to exceeding maximum file size.")
                    continue

                # Check total extracted size
                if total_extracted_size + member.size > max_total_extracted_size:
                    logging.warning(f"Skipping {member.name} due to exceeding maximum total extracted size.")
                    continue

                # Check number of files extracted
                if extracted_file_count >= max_files_to_extract:
                    logging.warning(f"Skipping {member.name} due to exceeding maximum number of files to extract.")
                    continue

                try:
                    tar.extract(member, '/tmp', numeric_owner=True)  # Prevent using names from archive
                    # Set the UID and GID of the extracted file
                    os.chown(extract_path, nobody_uid, nobody_gid)
                    logging.info(f"Extracted {member.name} to /tmp")
                    extracted_file_count += 1
                    total_extracted_size += member.size
                except Exception as e:
                    logging.error(f"Error extracting {member.name}: {e}")

    except FileNotFoundError:
        logging.error(f"File not found: {file_name}")
    except tarfile.ReadError:
        logging.error(f"Invalid tar file: {file_name}")
    except ValueError as e:
        logging.error(f"Error: {e}")
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")

def calculate_sha256(filename):
    """Calculates the SHA256 hash of a file."""
    sha256_hash = hashlib.sha256()
    with open(filename, "rb") as f:
        # Read and update hash string value in blocks of 4K
        for byte_block in iter(lambda: f.read(4096),b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()


if __name__ == '__main__':
    # Example usage (replace with your actual file)
    # Create a dummy tar file for testing
    import os
    import tempfile
    import shutil

    def create_test_tar(tar_filename):
        with tarfile.open(tar_filename, "w:gz") as tar:
            # Create a dummy file
            with open("test.txt", "w") as f:
                f.write("This is a test file.")
            tar.add("test.txt")
            os.remove("test.txt")

    # Create a temporary directory and a test tar file
    temp_dir = tempfile.mkdtemp()
    test_tar_file = os.path.join(temp_dir, "test.tar.gz")
    create_test_tar(test_tar_file)

    extract_tar(test_tar_file)

    # Clean up the temporary directory
    shutil.rmtree(temp_dir)

