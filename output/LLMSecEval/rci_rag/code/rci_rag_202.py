import zipfile
import os
import stat
import logging
import shutil
import resource  # For resource limits (Unix-like systems)
import unicodedata
import re

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def sanitize_filename(filename):
    """Sanitizes a filename to prevent various attacks."""
    # Normalize Unicode
    filename = unicodedata.normalize('NFKC', filename)
    # Remove control characters
    filename = re.sub(r'[\x00-\x1f\x7f]', '', filename)
    # Replace or remove potentially problematic characters
    filename = re.sub(r'[<>:"/\\|?*]', '_', filename)  # Replace with underscores
    # Remove leading/trailing whitespace
    filename = filename.strip()
    # Truncate to a reasonable length (optional)
    filename = filename[:255]
    return filename


def secure_extract_zip(zip_file_path, extract_path):
    """
    Securely extracts a zip archive to a specified directory.

    Args:
        zip_file_path (str): The path to the zip archive.
        extract_path (str): The directory to extract the contents to.
    """

    # Validate paths
    extract_path = os.path.realpath(extract_path)  # Resolve symlinks
    if not os.path.isabs(extract_path):
        raise ValueError("Extract path must be absolute.")

    # Create the extraction directory if it doesn't exist
    try:
        os.makedirs(extract_path, exist_ok=True)
    except OSError as e:
        logging.error(f"Failed to create extract directory: {e}")
        raise

    old_umask = os.umask(0o077)  # Restrictive umask (owner-only access)
    try:
        with zipfile.ZipFile(zip_file_path, 'r') as zip_ref:
            num_files = len(zip_ref.infolist())
            if num_files > 1000:  # Limit number of files
                raise ValueError("Too many files in zip archive (DoS protection)")

            total_extracted_size = 0
            max_extracted_size = 1024 * 1024 * 100  # 100MB limit

            for member in zip_ref.infolist():
                # Sanitize the filename
                member.filename = sanitize_filename(member.filename)

                # Construct the full path to the extracted file
                file_path = os.path.abspath(os.path.join(extract_path, member.filename))

                # Security checks:
                # 1. Prevent directory traversal
                if not file_path.startswith(os.path.abspath(extract_path) + os.sep):
                    logging.warning(f"Skipping potentially unsafe path: {member.filename}")
                    continue

                # 2. Check for symbolic links (more robust)
                if stat.S_ISLNK(member.external_attr >> 16):
                    try:
                        zip_ref.extract(member, extract_path)  # Extract the symlink
                        link_path = os.path.join(extract_path, member.filename)
                        target_path = os.readlink(link_path)
                        abs_target_path = os.path.abspath(os.path.join(os.path.dirname(link_path), target_path))

                        if not abs_target_path.startswith(os.path.abspath(extract_path) + os.sep):
                            logging.warning(f"Deleting unsafe symbolic link: {member.filename} -> {target_path}")
                            os.remove(link_path)  # Remove the unsafe symlink
                        else:
                            logging.info(f"Extracted symbolic link: {member.filename} -> {target_path}")

                    except OSError as e:
                        logging.error(f"Error handling symbolic link {member.filename}: {e}")
                        if os.path.exists(os.path.join(extract_path, member.filename)):
                            os.remove(os.path.join(extract_path, member.filename)) # Attempt to remove the broken symlink
                        continue  # Skip to the next member
                else:
                    # Extract the file (non-symlink)
                    try:
                        zip_ref.extract(member, extract_path)
                        total_extracted_size += member.file_size
                        if total_extracted_size > max_extracted_size:
                            raise ValueError("Total extracted size exceeded limit (DoS protection)")

                        # Explicitly set permissions (more secure than relying on external_attr)
                        os.chmod(file_path, stat.S_IRUSR | stat.S_IWUSR)  # Owner read/write

                    except OSError as e:
                        logging.error(f"OSError extracting {member.filename}: {e}")
                        # Handle disk full, permission denied, etc.
                        raise  # Or handle more gracefully
                    except IOError as e:
                        logging.error(f"IOError extracting {member.filename}: {e}")
                        # Handle file not found, etc.
                        raise
                    except Exception as e:
                        logging.error(f"Unexpected error extracting {member.filename}: {e}")
                        raise

    except zipfile.BadZipFile as e:
        logging.error(f"Invalid zip file: {e}")
        raise
    except FileNotFoundError:
        logging.error(f"Zip file not found: {zip_file_path}")
        raise
    except ValueError as e:
        logging.error(f"Value error: {e}")
        raise
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        raise
    finally:
        os.umask(old_umask)  # Restore original umask


if __name__ == '__main__':
    # Example usage:
    zip_file = 'archive.zip'  # Replace with your zip file
    extract_dir = '/tmp/unpack'  # Replace with your desired extraction directory

    # Create a dummy zip file for testing
    if not os.path.exists(zip_file):
        with zipfile.ZipFile(zip_file, 'w') as zf:
            zf.writestr("test.txt", "This is a test file.")
            zf.writestr("subdir/test2.txt", "This is another test file.")
            # Add a potentially malicious file
            zf.writestr("../evil.txt", "This should not be extracted.")
            zf.writestr("safe_dir/../../evil2.txt", "This should not be extracted either.")
            zf.writestr("safe_dir/. ./evil3.txt", "This should not be extracted either.")
            zf.writestr("symlink.txt", "This is a symlink.") # Add a symlink
            zf.writestr("test\u00A0file.txt", "Unicode test") # Add unicode test
            #zf.write("test.txt", "symlink.txt", zipfile.ZIP_STORED) # Create a symlink in the zip (requires more setup)


    try:
        secure_extract_zip(zip_file, extract_dir)
        logging.info(f"Successfully extracted {zip_file} to {extract_dir}")
    except Exception as e:
        logging.error(f"Extraction failed: {e}")
    finally:
        # Clean up the extraction directory (optional, for testing)
        shutil.rmtree(extract_dir, ignore_errors=True)
        pass

