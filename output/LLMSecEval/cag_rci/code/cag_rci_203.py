import os
import stat
import tarfile
import logging
import shutil
import magic  # Requires python-magic

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

ARCHIVE_PATH = 'archive.tar.gz'
EXTRACT_DIR = '/tmp/unpack'
ALLOWED_EXTENSIONS = ['.txt', '.pdf', '.jpg', '.png', '.csv']
ALLOWED_MIME_TYPES = ['text/plain', 'image/jpeg', 'image/png', 'application/pdf', 'text/csv']  # Example MIME types
ALLOWED_LOCATIONS = ['/tmp/unpack/']
DESIRED_FILE_PERMISSIONS = 0o640
DESIRED_DIR_PERMISSIONS = 0o750
OWNER_UID = 1000
OWNER_GID = 1000
MAX_EXTRACTED_SIZE = 1024 * 1024 * 100  # 100MB limit


def is_path_safe(path, base_dir):
    try:
        abs_path = os.path.realpath(path)
        abs_base_dir = os.path.realpath(base_dir)

        if not abs_path.startswith(abs_base_dir):
            logging.warning(f"Path traversal detected: {path} is outside of {base_dir}")
            return False

        return True
    except OSError as e:
        logging.error(f"Error resolving path: {e}")
        return False


def is_extension_allowed(filename, allowed_extensions):
    name, ext = os.path.splitext(filename)
    if not ext.lower() in allowed_extensions:
        return False
    _, base_ext = os.path.splitext(name)
    if base_ext:
        logging.warning(f"Double extension detected: {filename}")
        return False
    return True


def is_location_allowed(path, allowed_locations):
    abs_path = os.path.abspath(path)
    for allowed_location in allowed_locations:
        abs_allowed_location = os.path.abspath(allowed_location)
        if abs_allowed_location.endswith('/'):
            if abs_path.startswith(abs_allowed_location):
                return True
        else:
            if abs_path == abs_allowed_location:
                return True
    logging.warning(f"Extraction location {path} is not in the allowlist.")
    return False


def is_file_type_allowed(filepath, allowed_mime_types):
    """Checks if the file's MIME type is in the allowlist."""
    try:
        mime = magic.Magic(mime=True).from_file(filepath)
        if mime in allowed_mime_types:
            return True
        logging.warning(f"Disallowed MIME type: {mime} for file {filepath}")
        return False
    except Exception as e:
        logging.error(f"Error determining file type: {e}")
        return False


def extract_secure(archive_path, extract_dir, max_extracted_size=MAX_EXTRACTED_SIZE):
    extracted_size = 0

    if not os.path.exists(extract_dir):
        try:
            os.makedirs(extract_dir, mode=DESIRED_DIR_PERMISSIONS)
            os.chown(extract_dir, OWNER_UID, OWNER_GID)
        except OSError as e:
            logging.error(f"Failed to create extraction directory: {e}")
            return False

    original_umask = os.umask(0o007)
    try:
        with tarfile.open(archive_path, 'r') as tar:
            for member in tar.getmembers():
                extract_path = os.path.join(extract_dir, member.name)

                if not is_path_safe(extract_path, extract_dir):
                    logging.warning(f"Skipping unsafe path: {member.name}")
                    return False

                if not is_extension_allowed(member.name, ALLOWED_EXTENSIONS):
                    logging.warning(f"Skipping file with disallowed extension: {member.name}")
                    return False

                if not is_location_allowed(extract_path, ALLOWED_LOCATIONS):
                    logging.warning(f"Skipping file due to disallowed location: {member.name}")
                    return False

                if member.issym() or member.islnk():
                    logging.warning(f"Skipping symbolic link: {member.name}")
                    continue  # Skip symbolic links

                if member.islnk():
                    logging.warning(f"Skipping hard link: {member.name}")
                    continue  # Skip hard links

                try:
                    tar.extract(member, extract_dir)
                    filepath = os.path.join(extract_dir, member.name)
                    file_size = os.path.getsize(filepath)
                    extracted_size += file_size

                    if extracted_size > max_extracted_size:
                        logging.error(f"Extraction aborted: Exceeded maximum extracted size ({max_extracted_size} bytes)")
                        # Consider a more controlled cleanup here
                        # shutil.rmtree(extract_dir)
                        return False

                    if not is_file_type_allowed(filepath, ALLOWED_MIME_TYPES):
                        logging.warning(f"Skipping file with disallowed MIME type: {member.name}")
                        os.remove(filepath)  # Remove the file
                        continue  # Continue to the next file

                    try:
                        if member.isdir():
                            os.chmod(filepath, DESIRED_DIR_PERMISSIONS)
                        else:
                            os.chmod(filepath, DESIRED_FILE_PERMISSIONS)
                    except OSError as e:
                        logging.error(f"Failed to set permissions for {member.name}: {e}")
                        return False

                    try:
                        os.chown(filepath, OWNER_UID, OWNER_GID)
                    except OSError as e:
                        logging.error(f"Failed to set ownership for {member.name}: {e}")
                        return False

                except Exception as e:
                    logging.error(f"Failed to extract {member.name}: {e}")
                    return False

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
        os.umask(original_umask)


if __name__ == '__main__':
    # Create a dummy archive.tar.gz for testing
    if not os.path.exists(ARCHIVE_PATH):
        try:
            with tarfile.open(ARCHIVE_PATH, "w:gz") as tar:
                # Create a dummy file
                with open("/tmp/test.txt", "w") as f:
                    f.write("This is a test file.")
                tar.add("/tmp/test.txt", arcname="test.txt")
                os.remove("/tmp/test.txt")

                # Create a file with a disallowed extension
                with open("/tmp/test.exe", "w") as f:
                    f.write("This is a test executable.")
                tar.add("/tmp/test.exe", arcname="test.exe")
                os.remove("/tmp/test.exe")

                # Create a file with a double extension
                with open("/tmp/test.txt.exe", "w") as f:
                    f.write("This is a test executable with a double extension.")
                tar.add("/tmp/test.txt.exe", arcname="test.txt.exe")
                os.remove("/tmp/test.txt.exe")

                # Create a file with a path traversal attempt
                with open("/tmp/../../test_traversal.txt", "w") as f:
                    f.write("This is a test traversal file.")
                tar.add("/tmp/../../test_traversal.txt", arcname="../test_traversal.txt")
                os.remove("/tmp/../../test_traversal.txt")

                # Create a file in an allowed location
                os.makedirs("/tmp/unpack/allowed_dir", exist_ok=True)
                with open("/tmp/unpack/allowed_dir/test_allowed.txt", "w") as f:
                    f.write("This is a test allowed file.")
                tar.add("/tmp/unpack/allowed_dir/test_allowed.txt", arcname="allowed_dir/test_allowed.txt")
                os.remove("/tmp/unpack/allowed_dir/test_allowed.txt")
                os.rmdir("/tmp/unpack/allowed_dir")

                # Create a symbolic link
                os.symlink("/tmp/test.txt", "/tmp/test_symlink")
                tar.add("/tmp/test_symlink", arcname="test_symlink")
                os.remove("/tmp/test_symlink")

                # Create a hard link
                os.link("/tmp/test.txt", "/tmp/test_hardlink")
                tar.add("/tmp/test_hardlink", arcname="test_hardlink")
                os.remove("/tmp/test_hardlink")

                # Create a file that claims to be a text file but is actually an executable
                with open("/tmp/test.txt", "wb") as f:
                    f.write(b"\x7fELF")  # ELF magic number (executable)
                tar.add("/tmp/test.txt", arcname="test.txt")
                os.remove("/tmp/test.txt")


        except Exception as e:
            logging.error(f"Failed to create dummy archive: {e}")
            exit(1)

    success = extract_secure(ARCHIVE_PATH, EXTRACT_DIR)
    if success:
        print("Archive extraction completed successfully.")
    else:
        print("Archive extraction failed. See logs for details.")

