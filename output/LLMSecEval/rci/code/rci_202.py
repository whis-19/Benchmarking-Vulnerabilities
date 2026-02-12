import tarfile
import os
import logging
import tempfile

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def is_within_directory(directory, target):
    """
    Checks if the target path is within the specified directory.
    This prevents path traversal vulnerabilities.
    """
    abs_directory = os.path.abspath(directory)
    abs_target = os.path.abspath(target)

    prefix = os.path.commonprefix([abs_directory, abs_target])
    return prefix == abs_directory


def extract_tarfile(archive_path, extract_path):
    """
    Extracts a tar archive to a specified directory, preventing path traversal.

    Args:
        archive_path (str): The path to the tar archive file.
        extract_path (str): The directory to extract the contents to.

    Raises:
        FileNotFoundError: If the archive file does not exist.
        tarfile.ReadError: If the archive is invalid or corrupted.
        OSError: If there are issues creating directories or extracting files.
        Exception: For any other unexpected errors during extraction.
    """

    # Input validation: Check if the archive file exists
    if not os.path.exists(archive_path):
        logging.error(f"Archive file not found: {archive_path}")
        raise FileNotFoundError(f"Archive file not found: {archive_path}")

    # Resolve paths to prevent path traversal
    archive_path = os.path.abspath(archive_path)
    extract_path = os.path.abspath(extract_path)

    try:
        # Ensure the extract directory exists. Create it if it doesn't.
        if not os.path.exists(extract_path):
            logging.info(f"Creating extraction directory: {extract_path}")
            os.makedirs(extract_path)

        # Open the tarfile with appropriate error handling.
        try:
            logging.info(f"Opening tarfile: {archive_path}")
            with tarfile.open(archive_path, 'r') as tar:
                for member in tar.getmembers():
                    member_path = os.path.join(extract_path, member.name)

                    if not is_within_directory(extract_path, member_path):
                        logging.warning(f"Skipping potentially malicious path: {member.name}")
                        continue  # Skip to the next member

                    try:
                        tar.extract(member, path=extract_path, numeric_owner=True)  # Extract each member individually
                    except Exception as extract_err:
                        logging.error(f"Error extracting {member.name}: {extract_err}")
                        # Decide whether to continue or abort based on the severity of the error
                        # For critical errors, you might want to re-raise the exception
                        continue # Continue to the next member.  Consider re-raising if critical.

                # Post-extraction: Set safe permissions (optional, but recommended)
                for root, dirs, files in os.walk(extract_path):
                    for dir in dirs:
                        os.chmod(os.path.join(root, dir), 0o755)  # rwxr-xr-x
                    for file in files:
                        os.chmod(os.path.join(root, file), 0o644)  # rw-r--r--


        except tarfile.ReadError as e:
            logging.error(f"Error reading tarfile: {e}")
            raise  # Re-raise the exception to signal failure.
        except OSError as e:
            logging.error(f"OS error during extraction: {e}")
            raise  # Re-raise the exception to signal failure.
        except Exception as e:
            logging.error(f"An unexpected error occurred during extraction: {e}")
            raise  # Re-raise the exception to signal failure.

        logging.info(f"Successfully extracted '{archive_path}' to '{extract_path}'")

    except Exception as e:
        logging.error(f"Extraction failed: {e}")
        raise  # Re-raise the exception to signal failure.


if __name__ == '__main__':
    archive_file = 'archive.tar.gz'  # Replace with the actual path to your archive
    extract_directory = '/tmp/unpack'

    # Create a dummy archive.tar.gz for testing purposes
    # In a real scenario, this would be replaced with the actual archive file.
    try:
        # Create a dummy archive for testing
        if not os.path.exists(archive_file):
            logging.info(f"Creating dummy archive: {archive_file}")
            with tarfile.open(archive_file, "w:gz") as tar:
                # Create a dummy file to add to the archive
                with tempfile.NamedTemporaryFile(mode="w", delete=True) as tmp_file:
                    tmp_file.write("This is a dummy file for testing.")
                    tmp_file.flush()  # Ensure data is written to disk
                    tar.add(tmp_file.name, arcname="dummy_file.txt")  # Add with a specific name in the archive
                logging.info(f"Dummy archive created successfully.")

        extract_tarfile(archive_file, extract_directory)

    except FileNotFoundError as e:
        logging.error(f"File not found error: {e}")
    except tarfile.ReadError as e:
        logging.error(f"Tarfile read error: {e}")
    except OSError as e:
        logging.error(f"OS error: {e}")
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")

