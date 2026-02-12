import tarfile
import os
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

ARCHIVE_PATH = "archive.zip"
UNPACK_DIR = "/tmp/unpack"
ALLOWED_EXTENSIONS = {".txt", ".pdf", ".csv", ".jpg", ".jpeg", ".png"}
ALLOWED_UNPACK_LOCATIONS = {"/tmp/unpack", "/opt/data"}
ALLOWED_ARCHIVE_LOCATIONS = {"/tmp", "/opt/archives"}  # Example
MAX_EXTRACTED_SIZE = 1024 * 1024 * 100  # 100MB limit
MAX_COMPRESSION_RATIO = 100  # Example: Maximum 100x compression

def is_path_safe(path, base_path):
    """Checks if the given path is safe and does not allow path traversal."""
    try:
        abs_path = os.path.abspath(path)
        abs_base_path = os.path.abspath(base_path)
        if not abs_path.startswith(abs_base_path):
            logging.warning(f"Path traversal detected: {path} is outside of {base_path}")
            return False
        normalized_path = os.path.normpath(path)
        if ".." in normalized_path.split(os.sep):
            logging.warning(f"Path traversal detected: '..' found in path: {path}")
            return False
        return True
    except Exception as e:
        logging.error(f"Error during path validation: {e}")
        return False

def extract_tarfile_securely(archive_path, unpack_dir):
    """Opens a tarfile, validates file paths, and extracts its contents securely."""

    # Sanitize the archive path
    try:
        archive_path = os.path.abspath(archive_path)
    except Exception as e:
        logging.error(f"Invalid archive path: {e}")
        return False

    archive_allowed = False
    for allowed_path in ALLOWED_ARCHIVE_LOCATIONS:
        if archive_path.startswith(os.path.abspath(allowed_path)):
            archive_allowed = True
            break

    if not archive_allowed:
        logging.error(f"Archive path not allowed: {archive_path}")
        return False

    if not os.path.isfile(archive_path):
        logging.error(f"Archive file not found: {archive_path}")
        return False

    if unpack_dir not in ALLOWED_UNPACK_LOCATIONS:
        logging.error(f"Unpack directory not allowed: {unpack_dir}")
        return False

    extracted_size = 0

    try:
        if not os.path.exists(unpack_dir):
            os.makedirs(unpack_dir, mode=0o700)

        with tarfile.open(archive_path, "r") as tar:  # Autodetect compression
            for member in tar.getmembers():
                filename = member.name
                sanitized_filename = os.path.basename(filename)
                target_path = os.path.join(unpack_dir, sanitized_filename)  # Explicitly create target path

                if not is_path_safe(target_path, unpack_dir):
                    logging.warning(f"Skipping extraction of {filename} due to path traversal risk.")
                    continue

                _, file_extension = os.path.splitext(sanitized_filename)
                if file_extension.lower() not in ALLOWED_EXTENSIONS:
                    logging.warning(f"Skipping extraction of {filename} due to disallowed file extension: {file_extension}")
                    continue

                if member.issym() or member.islnk():
                    logging.warning(f"Skipping extraction of {filename} because it is a symlink.")
                    continue

                try:
                    # Check for zip bomb before extraction
                    if member.isfile():
                        extracted_size += member.size
                        if extracted_size > MAX_EXTRACTED_SIZE:
                            logging.error("Exceeded maximum extracted size.  Possible zip bomb.")
                            return False

                        compression_ratio = member.size / member.size  # Replace with actual compressed size if available
                        if compression_ratio > MAX_COMPRESSION_RATIO:
                            logging.error(f"Compression ratio too high ({compression_ratio:.2f}). Possible zip bomb.")
                            return False

                    # Extract to unpack_dir, but prevent attribute setting
                    tar.extract(member, path=unpack_dir, set_attrs=False)

                    # Rename the extracted file to the sanitized name
                    extracted_file_path = os.path.join(unpack_dir, member.name)
                    try:
                        os.rename(extracted_file_path, target_path)
                    except OSError as e:
                        logging.error(f"Error renaming {extracted_file_path} to {target_path}: {e}")
                        # Consider deleting the extracted file if rename fails

                    # Set permissions on directories
                    if member.isdir():
                        os.chmod(target_path, 0o700)  # Restrictive permissions for directories
                    else:
                        os.chmod(target_path, 0o600)  # Restrictive permissions for files

                except Exception as e:
                    logging.error(f"Error extracting {filename}: {e}")

        logging.info(f"Successfully extracted archive to {unpack_dir}")
        return True

    except tarfile.ReadError as e:
        logging.error(f"Error reading tarfile: {e}")
        return False
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        return False

if __name__ == "__main__":
    # ... (rest of the test code)
    pass

