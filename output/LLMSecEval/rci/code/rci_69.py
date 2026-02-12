import tarfile
import os
import shutil
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

MAX_EXTRACTED_SIZE_MB = 100  # Example: Limit total extracted size to 100MB
MAX_FILES_IN_ARCHIVE = 1000  # Example: Limit number of files in archive


def is_safe_path(extract_path, filename):
    """
    Checks if a filename, when joined with the extract_path, results in a safe path
    that is still within the extract_path directory.  This prevents path traversal.
    Handles symbolic links by resolving them to their real paths.
    """
    try:
        extract_path = os.path.abspath(extract_path)
        filepath = os.path.abspath(os.path.join(extract_path, filename))
        filepath = os.path.realpath(filepath)  # Resolve symbolic links
        return filepath.startswith(extract_path)

    except ValueError:
        return False


def extract_tarfile(archive_path, extract_path):
    """
    Extracts a tar archive to a specified directory, preventing path traversal and privilege escalation.

    Args:
        archive_path (str): The path to the tar archive file.
        extract_path (str): The directory to extract the contents to.
    """

    # Input Validation: Check if the archive path exists and is a file.
    if not os.path.exists(archive_path):
        logging.error(f"Archive file not found: {archive_path}")
        raise FileNotFoundError(f"Archive file not found: {archive_path}")

    if not os.path.isfile(archive_path):
        logging.error(f"Not a file: {archive_path}")
        raise ValueError(f"Not a file: {archive_path}")

    # Input Validation: Sanitize the extract path to prevent path traversal.
    extract_path = os.path.abspath(extract_path)  # Convert to absolute path
    if not os.path.exists(extract_path):
        try:
            os.makedirs(extract_path, exist_ok=True)  # Create if it doesn't exist
        except OSError as e:
            logging.error(f"Failed to create extract directory: {extract_path} - {e}")
            raise

    try:
        # Open the tarfile with appropriate error handling.
        try:
            with tarfile.open(archive_path, 'r') as tar:
                members = tar.getmembers()

                # DoS Prevention: Check number of files
                if len(members) > MAX_FILES_IN_ARCHIVE:
                    logging.warning(f"Archive contains too many files ({len(members)} > {MAX_FILES_IN_ARCHIVE}). Aborting extraction.")
                    raise ValueError("Archive contains too many files.")

                total_extracted_size = 0

                # Iterate through each member of the tarfile BEFORE extraction
                for member in members:
                    # Path Traversal Prevention: Check if the extracted path is safe.
                    if not is_safe_path(extract_path, member.name):
                        logging.warning(f"Path traversal attempt detected: {member.name}")
                        raise ValueError(f"Path traversal attempt detected: {member.name}")

                    # Symbolic Link Prevention: Reject symbolic links
                    if member.issym() or member.islnk():
                        logging.warning(f"Symbolic link detected: {member.name}.  Symbolic links are not allowed.")
                        raise ValueError("Symbolic links are not allowed.")

                    # DoS Prevention: Check total extracted size (basic example)
                    total_extracted_size += member.size
                    if total_extracted_size > MAX_EXTRACTED_SIZE_MB * 1024 * 1024:
                        logging.warning(f"Archive exceeds maximum allowed extracted size ({MAX_EXTRACTED_SIZE_MB} MB). Aborting extraction.")
                        raise ValueError("Archive exceeds maximum allowed extracted size.")


                # Extract all members to the specified directory.
                # Use extractall with numeric owner/group IDs to avoid potential privilege escalation.
                tar.extractall(path=extract_path, numeric_owner=True)

        except tarfile.ReadError as e:
            logging.error(f"Error reading tarfile: {e}")
            raise  # Re-raise the exception to signal failure.
        except OSError as e:
            logging.error(f"OSError during extraction: {e}")
            raise
        except ValueError as e:
            logging.error(f"ValueError during extraction: {e}")
            raise
        except Exception as e:
            logging.error(f"An unexpected error occurred during extraction: {e}")
            raise  # Re-raise the exception to signal failure.

        logging.info(f"Successfully extracted '{archive_path}' to '{extract_path}'")

    except Exception as e:
        logging.error(f"Extraction failed: {e}")
        # Consider logging the error for debugging purposes.
        raise  # Re-raise the exception to signal failure.  Important for calling code to know extraction failed.


if __name__ == '__main__':
    archive_file = 'archive.tar.gz'  # Replace with the actual path to your archive
    extract_directory = '/tmp/unpack'

    # Create a dummy archive.tar.gz for testing purposes
    # In a real scenario, this would be replaced with the actual archive file.
    try:
        # Create a dummy archive for testing
        if not os.path.exists(archive_file):
            with tarfile.open(archive_file, "w:gz") as tar:
                # Create a dummy file to add to the archive
                dummy_file_path = "dummy_file.txt"
                try:
                    with open(dummy_file_path, "w") as f:
                        f.write("This is a dummy file for testing.")
                    # Ensure we add the file safely, resolving symlinks if necessary
                    tar.add(dummy_file_path, arcname=os.path.basename(dummy_file_path)) # Add with original name
                except OSError as e:
                    logging.error(f"Error creating dummy file: {e}")
                    raise
                finally:
                    try:
                        os.remove(dummy_file_path)  # Clean up the dummy file
                    except OSError as e:
                        logging.warning(f"Error removing dummy file: {e}")

        extract_tarfile(archive_file, extract_directory)

    except Exception as e:
        logging.error(f"An error occurred: {e}")

