import tarfile
import os
import shutil
import tempfile
import logging

# Configure logging (optional, but recommended for production)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB (adjust as needed)
MAX_FILE_COUNT = 1000  # (adjust as needed)
MAX_TOTAL_EXTRACTED_SIZE = 100 * 1024 * 1024  # 100 MB (adjust as needed)
ALLOWED_DESTINATION = "/tmp/unpack"  # Or a list of allowed destinations.  Adjust as needed.


def secure_extract_tarfile(tarfile_path, destination_dir=ALLOWED_DESTINATION):
    """
    Securely extracts a tarfile to a specified destination directory.

    This function addresses potential security vulnerabilities associated with tarfile extraction,
    including path traversal, denial-of-service attacks, and more.

    Args:
        tarfile_path (str): The path to the tarfile to extract.
        destination_dir (str): The directory to extract the tarfile to.  Defaults to /tmp/unpack.

    Raises:
        ValueError: If the tarfile path is invalid or the destination directory is unsafe.
        OSError: If there are issues creating directories or extracting files.
        tarfile.ReadError: If the tarfile is corrupted or invalid.
        Exception: For any other unexpected errors during extraction.
    """

    temp_dir = None
    tarfile_path_local = None  # Use a local variable to avoid shadowing
    extracted_dir = None

    # 1. Input Validation and Sanitization
    if not isinstance(tarfile_path, str) or not tarfile_path:
        raise ValueError("Invalid tarfile path.")

    if not isinstance(destination_dir, str) or not destination_dir:
        raise ValueError("Invalid destination directory.")

    # Check if the tarfile exists
    if not os.path.exists(tarfile_path):
        raise ValueError(f"Tarfile not found: {tarfile_path}")

    # 2. Directory Handling and Security Checks

    # Create the destination directory if it doesn't exist
    try:
        os.makedirs(destination_dir, exist_ok=True)  # exist_ok=True prevents errors if the directory already exists
    except OSError as e:
        logging.error(f"Error creating destination directory: {e}")
        raise OSError(f"Failed to create destination directory: {e}")

    # Resolve the absolute path of the destination directory
    destination_dir = os.path.abspath(destination_dir)

    # Security: Prevent extraction outside the intended destination directory
    allowed_destination_real = os.path.realpath(ALLOWED_DESTINATION)
    destination_dir_real = os.path.realpath(destination_dir)

    if not destination_dir_real.startswith(allowed_destination_real):
        logging.warning(f"Destination directory is not a subdirectory of {ALLOWED_DESTINATION}. Using a temporary directory instead.")
        destination_dir = tempfile.mkdtemp(prefix="secure_unpack_", dir="/tmp")  # Create a secure temporary directory
        logging.info(f"Using temporary directory: {destination_dir}")

    # 3. Tarfile Extraction with Security Measures
    try:
        with tarfile.open(tarfile_path, "r") as tar:
            def is_within_directory(directory, target):
                abs_directory = os.path.abspath(directory)
                abs_target = os.path.abspath(target)
                prefix = os.path.commonprefix([abs_directory, abs_target])
                return prefix == abs_directory

            extracted_file_count = 0
            total_extracted_size = 0

            for member in tar.getmembers():
                member_path = os.path.join(destination_dir, member.name)

                # Path Traversal Check
                if not is_within_directory(destination_dir, member_path):
                    logging.error(f"Path traversal attempt detected for: {member.name}")
                    raise Exception(f"Attempted Path Traversal in Tar File: {member.name}")

                # Skip hard links and symlinks
                if member.islnk() or member.issym():
                    logging.warning(f"Skipping hard link or symlink: {member.name}")
                    continue

                # Skip special files
                if member.type not in (tarfile.REGTYPE, tarfile.DIRTYPE, tarfile.AREGTYPE):
                    logging.warning(f"Skipping special file: {member.name} (type: {member.type})")
                    continue

                # Check file size limit
                if member.isfile() and member.size > MAX_FILE_SIZE:
                    logging.warning(f"File size exceeds limit: {member.name} ({member.size} bytes). Skipping extraction.")
                    continue

                # Check file count limit
                extracted_file_count += 1
                if extracted_file_count > MAX_FILE_COUNT:
                    logging.warning(f"File count exceeds limit ({MAX_FILE_COUNT}). Stopping extraction.")
                    break

                # Check total extracted size limit
                total_extracted_size += member.size
                if total_extracted_size > MAX_TOTAL_EXTRACTED_SIZE:
                    logging.warning(f"Total extracted size exceeds limit ({MAX_TOTAL_EXTRACTED_SIZE} bytes). Stopping extraction.")
                    break

                # Prevent file overwrites (attempt with exclusive creation)
                try:
                    if member.isfile():
                        # Attempt exclusive file creation
                        fd = os.open(member_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)  # Adjust permissions as needed
                        with open(fd, 'wb') as outfile:
                            outfile.write(tar.extractfile(member).read()) # Read the file content from tarfile and write to the new file
                        os.close(fd)  # Close the file descriptor
                    else:
                        tar.extract(member, path=destination_dir, numeric_owner=True)
                except FileExistsError:
                    logging.warning(f"File already exists: {member_path}. Skipping extraction.")
                    continue
                except Exception as extract_err:
                    logging.error(f"Error extracting {member.name}: {extract_err}")
                    raise

                logging.debug(f"Extracted: {member.name} to {member_path}")

    except tarfile.ReadError as e:
        logging.error(f"Error reading tarfile: {e}")
        raise tarfile.ReadError(f"Invalid or corrupted tarfile: {e}")
    except Exception as e:
        logging.error(f"Error extracting tarfile: {e}")
        raise Exception(f"Error during tarfile extraction: {e}")
    finally:
        # Clean up the temporary files and directories
        if temp_dir and os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)

    logging.info(f"Successfully extracted tarfile to: {destination_dir}")
    return destination_dir  # Return the destination directory for further processing


# Example Usage (with error handling):
if __name__ == "__main__":
    # Create a dummy tarfile for testing
    temp_dir = None
    tarfile_path_local = None
    extracted_dir = None

    try:
        # Create a temporary directory
        temp_dir = tempfile.mkdtemp()

        # Create a file inside the temporary directory
        test_file_path = os.path.join(temp_dir, "test.txt")
        with open(test_file_path, "w") as f:
            f.write("This is a test file.")

        # Create a tarfile from the temporary directory
        tarfile_path_local = os.path.join(tempfile.gettempdir(), "test.tar.gz")
        with tarfile.open(tarfile_path_local, "w:gz") as tar:
            tar.add(temp_dir, arcname="test_dir")  # Add the directory, not just the file

        # Extract the tarfile securely
        extracted_dir = secure_extract_tarfile(tarfile_path_local)
        print(f"Tarfile extracted to: {extracted_dir}")

        # Verify the extraction
        extracted_file_path = os.path.join(extracted_dir, "test_dir", "test.txt")
        if os.path.exists(extracted_file_path):
            print("Extraction successful!")
        else:
            print("Extraction failed.")

    except ValueError as e:
        print(f"ValueError: {e}")
    except OSError as e:
        print(f"OSError: {e}")
    except tarfile.ReadError as e:
        print(f"Tarfile ReadError: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
    finally:
        # Clean up the temporary files and directories
        if temp_dir and os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)
        if tarfile_path_local and os.path.exists(tarfile_path_local):
            os.remove(tarfile_path_local)
        if extracted_dir and os.path.exists(extracted_dir):
            shutil.rmtree(extracted_dir, ignore_errors=True)  # Remove the extracted directory

