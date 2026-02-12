import os
import tarfile
import logging
import stat
import magic
import uuid
import re

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

ARCHIVE_PATH = "archive.tar.gz"
UNPACK_DIR = "/tmp/unpack"
ALLOWED_EXTENSIONS = {".txt", ".pdf", ".csv", ".jpg", ".jpeg", ".png"}  # Example allowlist
ALLOWED_UNPACK_LOCATIONS = {"/tmp/unpack", "/opt/data"} # Example allowlist

def is_path_safe(base_path, target_path):
    """
    Checks if the target path is within the allowed base path and prevents path traversal.
    """
    try:
        # Normalize paths to prevent bypasses
        base_path = os.path.abspath(base_path)
        target_path = os.path.abspath(target_path)

        # Check if the target path starts with the base path using commonpath
        common_path = os.path.commonpath([base_path, target_path])
        if common_path != base_path:
            return False

        # Check if the target path starts with the base path
        return target_path.startswith(base_path)
    except OSError as e:
        logging.error(f"Path validation error: {e}")
        return False

def sanitize_filename(filename):
    """
    Sanitizes a filename to remove potentially dangerous characters.
    """
    # Remove or replace characters that could be interpreted as path separators
    # or special characters.  This is a basic example; you might need to
    # customize it based on your specific requirements.
    sanitized_filename = re.sub(r"[^a-zA-Z0-9._-]", "_", filename)
    return sanitized_filename

def extract_tarfile_securely(archive_path, unpack_dir, max_archive_size=1024*1024*100, max_file_count=1000, max_depth=10): # Example limits
    """
    Extracts a tarfile securely, preventing path traversal and other vulnerabilities.
    """

    # Validate archive path
    if not os.path.isfile(archive_path):
        logging.error(f"Archive file not found: {archive_path}")
        return False

    # Validate unpack directory
    if unpack_dir not in ALLOWED_UNPACK_LOCATIONS:
        logging.error(f"Unpack directory not allowed: {unpack_dir}")
        return False

    # Create unpack directory if it doesn't exist
    try:
        os.makedirs(unpack_dir, exist_ok=True)
    except OSError as e:
        logging.error(f"Failed to create unpack directory: {e}")
        return False

    archive_size = os.path.getsize(archive_path)
    if archive_size > max_archive_size:
        logging.error(f"Archive size exceeds maximum allowed size ({max_archive_size} bytes)")
        return False

    original_umask = os.umask(0o077)  # Set umask to 077 (no access for group/others)
    file_count = 0
    try:
        with tarfile.open(archive_path, "r") as tar:
            for member in tar.getmembers():
                file_count += 1
                if file_count > max_file_count:
                    logging.error(f"Archive contains more than the maximum allowed number of files ({max_file_count})")
                    return False

                # Check directory depth
                depth = member.name.count('/')
                if depth > max_depth:
                    logging.error(f"Archive contains files with a directory depth exceeding the maximum allowed depth ({max_depth})")
                    return False

                # Sanitize filename
                filename = member.name
                filename = sanitize_filename(filename) # Sanitize the filename

                if member.issym():  # Check if it's a symbolic link
                    logging.warning(f"Skipping symbolic link: {filename}")
                    continue
                if ".." in filename:
                    logging.warning(f"Skipping entry due to potential path traversal: {filename}")
                    continue

                # Construct the full extraction path
                target_path = os.path.join(unpack_dir, filename)

                # Canonicalize the path
                target_path = os.path.abspath(target_path) # Use abspath instead of realpath

                # Validate the target path
                if not is_path_safe(unpack_dir, target_path):
                    logging.warning(f"Skipping entry due to path traversal prevention: {filename}")
                    continue

                # Validate file extension
                _, ext = os.path.splitext(filename)
                if ext.lower() not in ALLOWED_EXTENSIONS:
                    logging.warning(f"Skipping entry due to disallowed extension: {filename}")
                    continue

                try:
                    # Generate a unique temporary filename
                    temp_filename = "." + str(uuid.uuid4()) + ".tmp"
                    temp_path = os.path.join(unpack_dir, temp_filename)

                    # Extract to the temporary location
                    tar.extract(member, path=unpack_dir, numeric_owner=True)
                    extracted_path = os.path.join(unpack_dir, filename)

                    # Rename the extracted file to the temporary file
                    os.rename(extracted_path, temp_path)

                    # Content-based inspection on the temporary file
                    mime = magic.Magic(mime=True)
                    file_type = mime.from_file(temp_path)

                    if "image" in file_type:
                        new_extension = ".jpg"  # Or .png, depending on the actual image type
                    elif "text" in file_type:
                        new_extension = ".txt"
                    elif "pdf" in file_type:
                        new_extension = ".pdf"
                    else:
                        logging.warning(f"Unknown file type for {filename}: {file_type}")
                        os.remove(temp_path)  # Remove unknown files
                        continue

                    # Rename the file
                    new_path = os.path.splitext(extracted_path)[0] + new_extension
                    final_path = os.path.splitext(temp_path)[0] + new_extension

                    # Atomically move the temporary file to its final destination
                    try:
                        os.replace(temp_path, final_path)
                    except PermissionError as e:
                        logging.error(f"Permission error renaming {temp_path} to {final_path}: {e}")
                    except FileExistsError as e:
                        logging.error(f"File already exists at {final_path}: {e}")
                    except OSError as e:
                        logging.error(f"OS error renaming {temp_path} to {final_path}: {e}")
                        raise # Re-raise the exception to trigger cleanup

                    extracted_path = final_path # Update extracted_path for permission setting

                    # Apply secure file permissions (read-only for owner, no access for group/others)
                    os.chmod(extracted_path, stat.S_IREAD)  # Read-only for owner

                    logging.info(f"Extracted and renamed: {filename} to {final_path} (Type: {file_type})")

                except Exception as e:
                    logging.error(f"Failed to extract {filename}: {e}")
                    # Attempt to clean up partially extracted files
                    try:
                        os.remove(temp_path)  # Remove the temporary file
                        logging.info(f"Removed partially extracted file: {filename}")
                    except OSError as e2:
                        logging.warning(f"Failed to remove partially extracted file {filename}: {e2}")
                    continue # Continue to the next file in the archive

        logging.info("Archive extracted successfully (with security checks).")
        return True

    except tarfile.ReadError as e:
        logging.error(f"Tarfile read error: {e}")
        return False
    except FileNotFoundError as e:
        logging.error(f"File not found: {e}")
        return False
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        return False
    finally:
        os.umask(original_umask)  # Restore original umask


if __name__ == "__main__":
    # Create a dummy archive.tar.gz for testing
    if not os.path.exists(ARCHIVE_PATH):
        try:
            with tarfile.open(ARCHIVE_PATH, "w:gz") as tar:
                # Create a dummy file inside the archive
                with open("dummy.txt", "w") as f:
                    f.write("This is a dummy file.")
                tar.add("dummy.txt")
                os.remove("dummy.txt") # Clean up the dummy file
            print(f"Created dummy archive: {ARCHIVE_PATH}")
        except Exception as e:
            print(f"Error creating dummy archive: {e}")

    success = extract_tarfile_securely(ARCHIVE_PATH, UNPACK_DIR)
    if success:
        print(f"Archive '{ARCHIVE_PATH}' extracted securely to '{UNPACK_DIR}'")
    else:
        print(f"Archive extraction failed. See logs for details.")

