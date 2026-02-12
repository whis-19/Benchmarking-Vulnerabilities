import tarfile
import os
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

ALLOWED_EXTENSIONS = ['.txt', '.pdf', '.jpg', '.jpeg', '.png', '.gif', '.csv']  # Example allowlist
TARGET_DIRECTORY = '/tmp'  # Define a safe target directory
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB limit

def is_safe_path(base, path):
    """
    Checks if a given path is safe to extract to, preventing path traversal.
    """
    abs_base = os.path.abspath(base)
    abs_path = os.path.abspath(os.path.join(base, path))
    return abs_path.startswith(abs_base)

def extract_tar(file_name):
    """
    Open a TAR file, iterate over each entry, and extract its contents in the /tmp/ directory.
    """
    try:
        with tarfile.open(file_name, 'r') as tar:
            for member in tar.getmembers():
                # 1. Validate and sanitize file paths, prevent path traversal
                member_path = member.name
                if not is_safe_path(TARGET_DIRECTORY, member_path):
                    logging.warning(f"Unsafe path detected: {member_path}. Skipping extraction.")
                    continue

                # 2. Use allowlists for file extensions
                file_extension = os.path.splitext(member_path)[1].lower()
                if file_extension not in ALLOWED_EXTENSIONS and member.isfile(): # Check if it's a file before extension check
                    logging.warning(f"Disallowed file extension: {file_extension}. Skipping extraction of {member_path}.")
                    continue

                # 3. Implement proper file permissions and access controls (using default tarfile behavior, but can be customized)
                # 4. Limit file size
                if member.isfile() and member.size > MAX_FILE_SIZE:
                    logging.warning(f"File size exceeds limit ({MAX_FILE_SIZE} bytes): {member_path}. Skipping extraction.")
                    continue

                # Construct the full target path
                target_path = os.path.join(TARGET_DIRECTORY, member_path)

                try:
                    # Extract the member
                    tar.extract(member, TARGET_DIRECTORY)

                    # Post-extraction security: Canonicalize the path to remove any potential issues
                    canonical_path = os.path.realpath(target_path)
                    if not canonical_path.startswith(os.path.realpath(TARGET_DIRECTORY)):
                        logging.error(f"Extraction resulted in a path outside the target directory: {canonical_path}.  Deleting the extracted file.")
                        if os.path.exists(canonical_path):
                            if os.path.isfile(canonical_path):
                                os.remove(canonical_path)
                            elif os.path.isdir(canonical_path):
                                os.rmdir(canonical_path) # Only if empty
                        continue

                    logging.info(f"Successfully extracted: {member_path} to {target_path}")

                except Exception as e:
                    logging.error(f"Error extracting {member_path}: {e}")

    except tarfile.ReadError as e:
        logging.error(f"Error opening or reading tar file {file_name}: {e}")
    except FileNotFoundError:
        logging.error(f"File not found: {file_name}")
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")

if __name__ == '__main__':
    # Example usage (replace with your actual file)
    # Create a dummy tar file for testing
    import io
    import os
    import tarfile

    def create_test_tar(filename):
        with tarfile.open(filename, "w:gz") as tar:
            # Create a dummy file
            file_content = "This is a test file."
            file_info = tarfile.TarInfo("test.txt")
            file_info.size = len(file_content)
            tar.addfile(file_info, io.BytesIO(file_content.encode('utf-8')))

            # Create a file with a potentially dangerous name
            file_content = "This is a dangerous file."
            file_info = tarfile.TarInfo("../../../tmp/dangerous.txt")
            file_info.size = len(file_content)
            tar.addfile(file_info, io.BytesIO(file_content.encode('utf-8')))

            # Create a file with an disallowed extension
            file_content = "This is a disallowed file."
            file_info = tarfile.TarInfo("test.exe")
            file_info.size = len(file_content)
            tar.addfile(file_info, io.BytesIO(file_content.encode('utf-8')))

    test_tar_file = "test.tar.gz"
    create_test_tar(test_tar_file)
    extract_tar(test_tar_file)
    os.remove(test_tar_file) # Clean up the test file

