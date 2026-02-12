import os
import stat
import tarfile
import logging
import shutil
import tempfile

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

ALLOWED_EXTENSIONS = ['.txt', '.pdf', '.jpg', '.png', '.csv']  # Example allowlist
ALLOWED_LOCATIONS = ['/tmp/unpack/']  # Example allowlist for locations (note the trailing slash)
DESIRED_FILE_PERMISSIONS = 0o640  # rw-r-----
DESIRED_DIR_PERMISSIONS = 0o750  # rwxr-x---
OWNER_UID = 1000  # Replace with the desired user ID
OWNER_GID = 1000  # Replace with the desired group ID
MAX_EXTRACTED_SIZE = 1024 * 1024 * 100  # 100MB limit


def is_path_safe(path, base_dir):
    """
    Checks if the given path is safe and does not contain path traversal vulnerabilities.
    Uses realpath for robust path resolution.
    """
    try:
        abs_path = os.path.realpath(path)
        abs_base_dir = os.path.realpath(base_dir)

        if not os.path.isabs(base_dir):
            raise ValueError("base_dir must be an absolute path")

        if not abs_path.startswith(abs_base_dir):
            logging.warning(f"Path traversal detected: {path} is outside of {base_dir}")
            return False

        return True
    except OSError as e:
        logging.error(f"Error resolving path: {e}")
        return False


def is_extension_allowed(filename, allowed_extensions):
    """
    Checks if the file extension is in the allowlist and prevents double extensions.
    """
    filename = os.path.basename(filename)  # Normalize the filename
    name, ext = os.path.splitext(filename)
    if not ext.lower() in allowed_extensions:
        return False
    # Check for double extensions
    _, base_ext = os.path.splitext(name)
    if base_ext:
        logging.warning(f"Double extension detected: {filename}")
        return False
    return True


def is_location_allowed(path, allowed_locations):
    """
    Checks if the extraction location is in the allowlist.
    Uses a more precise prefix check.
    """
    abs_path = os.path.abspath(path)
    for allowed_location in allowed_locations:
        abs_allowed_location = os.path.abspath(allowed_location)
        # Check if the allowed location ends with a slash to prevent prefix issues
        if abs_allowed_location.endswith('/'):
            if abs_path.startswith(abs_allowed_location):
                return True
        else:
            # If it doesn't end with a slash, check for an exact match
            if abs_path == abs_allowed_location:
                return True
    logging.warning(f"Extraction location {path} is not in the allowlist.")
    return False


def extract_secure(archive_path, extract_dir, max_extracted_size=MAX_EXTRACTED_SIZE):
    """
    Extracts files from a tar archive securely, with size limits and other security checks.
    """
    extracted_size = 0
    extracted_files = []  # Keep track of extracted files

    # Create the extraction directory if it doesn't exist
    if not os.path.exists(extract_dir):
        try:
            os.makedirs(extract_dir, mode=DESIRED_DIR_PERMISSIONS)
            os.chown(extract_dir, OWNER_UID, OWNER_GID)
        except OSError as e:
            logging.error(f"Failed to create extraction directory: {e}")
            return False

    original_umask = os.umask(0o007)  # Set umask to 007 (rwxrwx---)
    try:
        with tarfile.open(archive_path, 'r') as tar:
            for member in tar.getmembers():
                # Construct the full extraction path
                extract_path = os.path.join(extract_dir, member.name)

                # Security checks
                if member.issym() or member.islnk():
                    logging.warning(f"Skipping symbolic link: {member.name}")
                    continue

                if not is_path_safe(extract_path, extract_dir):
                    logging.warning(f"Skipping unsafe path: {member.name}")
                    return False  # Fail fast

                if not is_extension_allowed(member.name, ALLOWED_EXTENSIONS):
                    logging.warning(f"Skipping file with disallowed extension: {member.name}")
                    return False  # Fail fast

                if not is_location_allowed(extract_path, ALLOWED_LOCATIONS):
                    logging.warning(f"Skipping file due to disallowed location: {member.name}")
                    return False  # Fail fast

                try:
                    # Extract the member
                    tar.extract(member, extract_dir)
                    filepath = os.path.join(extract_dir, member.name)
                    file_size = os.path.getsize(filepath)
                    extracted_size += file_size
                    extracted_files.append(filepath)  # Add to the list

                    if extracted_size > max_extracted_size:
                        logging.error(f"Extraction aborted: Exceeded maximum extracted size ({max_extracted_size} bytes)")
                        # Clean up ONLY the extracted files
                        for file_to_remove in extracted_files:
                            try:
                                os.remove(file_to_remove)
                            except OSError as e:
                                logging.error(f"Failed to remove {file_to_remove}: {e}")
                        return False

                    # Set file permissions and ownership
                    try:
                        if member.isdir():
                            os.chmod(filepath, DESIRED_DIR_PERMISSIONS)
                        else:
                            os.chmod(filepath, DESIRED_FILE_PERMISSIONS)
                    except OSError as e:
                        logging.error(f"Failed to set permissions for {member.name}: {e}")
                        return False  # Fail fast

                    try:
                        os.chown(filepath, OWNER_UID, OWNER_GID)
                    except OSError as e:
                        logging.error(f"Failed to set ownership for {member.name}: {e}")
                        return False  # Fail fast

                except Exception as e:
                    logging.error(f"Failed to extract {member.name}: {e}")
                    return False # Fail fast

            logging.info(f"Successfully extracted archive to {extract_dir}")
            return True

    except FileNotFoundError:
        logging.error(f"Archive not found: {archive_path}")
        return False
    except tarfile.ReadError as e:
        logging.error(f"Error reading archive: {e}")
        return False
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        return False
    finally:
        os.umask(original_umask)  # Restore original umask


if __name__ == '__main__':
    # Create a temporary directory
    temp_dir = tempfile.mkdtemp()
    archive_path = os.path.join(temp_dir, "archive.tar.gz")
    extract_dir = os.path.join(temp_dir, "unpack")

    try:
        # Create a dummy archive in the temporary directory
        with tarfile.open(archive_path, "w:gz") as tar:
            # Create a dummy file
            with open(os.path.join(temp_dir, "test.txt"), "w") as f:
                f.write("This is a test file.")
            tar.add(os.path.join(temp_dir, "test.txt"), arcname="test.txt")
            os.remove(os.path.join(temp_dir, "test.txt"))

            # Create a file with a disallowed extension
            with open(os.path.join(temp_dir, "test.exe"), "w") as f:
                f.write("This is a test executable.")
            tar.add(os.path.join(temp_dir, "test.exe"), arcname="test.exe")
            os.remove(os.path.join(temp_dir, "test.exe"))

            # Create a file with a path traversal attempt
            with open(os.path.join(temp_dir, "test_traversal.txt"), "w") as f:
                f.write("This is a test traversal file.")
            tar.add(os.path.join(temp_dir, "test_traversal.txt"), arcname="../test_traversal.txt")
            os.remove(os.path.join(temp_dir, "test_traversal.txt"))

            # Create a file in an allowed location
            os.makedirs(os.path.join(temp_dir, "unpack", "allowed_dir"), exist_ok=True)
            with open(os.path.join(temp_dir, "unpack", "allowed_dir", "test_allowed.txt"), "w") as f:
                f.write("This is a test allowed file.")
            tar.add(os.path.join(temp_dir, "unpack", "allowed_dir", "test_allowed.txt"), arcname="allowed_dir/test_allowed.txt")
            os.remove(os.path.join(temp_dir, "unpack", "allowed_dir", "test_allowed.txt"))
            os.rmdir(os.path.join(temp_dir, "unpack", "allowed_dir"))

            # Create a file with a double extension
            with open(os.path.join(temp_dir, "test.txt.exe"), "w") as f:
                f.write("This is a test double extension file.")
            tar.add(os.path.join(temp_dir, "test.txt.exe"), arcname="test.txt.exe")
            os.remove(os.path.join(temp_dir, "test.txt.exe"))

        success = extract_secure(archive_path, extract_dir)
        if success:
            print("Archive extraction completed successfully.")
        else:
            print("Archive extraction failed. See logs for details.")

    except Exception as e:
        logging.error(f"Test failed: {e}")
    finally:
        # Clean up the temporary directory
        shutil.rmtree(temp_dir)

