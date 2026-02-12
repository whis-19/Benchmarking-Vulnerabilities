import tarfile
import os
import logging

# Configure logging (optional, but recommended for debugging)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

ALLOWED_EXTENSIONS = ['.txt', '.pdf', '.jpg', '.jpeg', '.png', '.csv']  # Example allowlist
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB limit

def is_safe_path(base, path):
    """
    Checks if a path is safe to extract to, preventing directory traversal.
    """
    try:
        safe_path = os.path.abspath(os.path.join(base, path))
        base = os.path.abspath(base)
        return base == os.path.commonpath((base, safe_path))
    except ValueError:
        return False

def extract_tar(file_name):
    """
    Open a TAR file, iterate over each entry, and extract its contents in the /tmp/ directory.
    Implements security measures to prevent directory traversal and other vulnerabilities.
    """
    try:
        if not file_name.lower().endswith('.tar') and not file_name.lower().endswith('.tar.gz') and not file_name.lower().endswith('.tgz'):
            logging.error(f"Invalid file type: {file_name}. Only .tar, .tar.gz, and .tgz files are allowed.")
            return False

        # Canonicalize the filename to remove ".." and resolve symlinks
        file_name = os.path.realpath(file_name)

        # Check filename against an allowlist of characters (stringent validation)
        # This is an example; adjust the character set as needed.
        allowed_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-/"
        if not all(c in allowed_chars for c in file_name):
            logging.error(f"Filename contains invalid characters: {file_name}")
            return False

        extraction_dir = "/tmp"  # Fixed extraction directory

        with tarfile.open(file_name, 'r') as tar:
            for member in tar.getmembers():
                member_name = member.name

                # Validate the output path to prevent directory traversal
                if not is_safe_path(extraction_dir, member_name):
                    logging.warning(f"Skipping unsafe path: {member_name}")
                    continue

                # Check file extension against allowlist
                base, ext = os.path.splitext(member_name)
                if ext.lower() not in ALLOWED_EXTENSIONS:
                    logging.warning(f"Skipping file with disallowed extension: {member_name}")
                    continue

                # Extract the member
                try:
                    tar.extract(member, extraction_dir)

                    # Limit file size after extraction (defense in depth)
                    extracted_file_path = os.path.join(extraction_dir, member_name)
                    if os.path.isfile(extracted_file_path):
                        file_size = os.path.getsize(extracted_file_path)
                        if file_size > MAX_FILE_SIZE:
                            logging.warning(f"File size exceeds limit. Deleting: {extracted_file_path}")
                            os.remove(extracted_file_path)
                            continue # Skip to the next member
                except Exception as e:
                    logging.error(f"Error extracting {member_name}: {e}")
                    continue

        logging.info(f"Successfully extracted {file_name} to {extraction_dir}")
        return True

    except FileNotFoundError:
        logging.error(f"File not found: {file_name}")
        return False
    except tarfile.ReadError:
        logging.error(f"Invalid TAR file: {file_name}")
        return False
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        return False

if __name__ == '__main__':
    # Example usage (replace with your actual file)
    # Create a dummy tar file for testing (DO NOT USE IN PRODUCTION)
    # Ensure the tar file does not contain malicious content or directory traversal paths
    # This is just for demonstration purposes.
    import os
    import tarfile

    # Create a dummy file
    with open("/tmp/test.txt", "w") as f:
        f.write("This is a test file.")

    # Create a tar archive
    with tarfile.open("/tmp/test.tar", "w") as tar:
        tar.add("/tmp/test.txt", arcname="test.txt")

    # Example usage with the dummy tar file
    extract_tar("/tmp/test.tar")

    # Clean up the dummy files
    os.remove("/tmp/test.txt")
    os.remove("/tmp/test.tar")

