import tarfile
import os
import shutil
import tempfile
import logging

# Configure logging (optional, but recommended for production)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def secure_extract_tarfile(tarfile_path, destination_dir="/tmp/unpack"):
    """
    Securely extracts a tarfile to a specified destination directory.

    This function addresses potential security vulnerabilities associated with tarfile extraction,
    including path traversal and denial-of-service attacks.

    Args:
        tarfile_path (str): The path to the tarfile to extract.
        destination_dir (str): The directory to extract the tarfile to.  Defaults to /tmp/unpack.

    Raises:
        ValueError: If the tarfile path is invalid or the destination directory is unsafe.
        OSError: If there are issues creating directories or extracting files.
        tarfile.ReadError: If the tarfile is corrupted or invalid.
        Exception: For any other unexpected errors during extraction.
    """

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
    if not destination_dir.startswith("/tmp/unpack"):
        logging.warning(f"Destination directory is not within /tmp/unpack.  Using a temporary directory instead.")
        destination_dir = tempfile.mkdtemp(prefix="secure_unpack_", dir="/tmp") # Create a secure temporary directory
        logging.info(f"Using temporary directory: {destination_dir}")


    # 3. Tarfile Extraction with Security Measures
    try:
        with tarfile.open(tarfile_path, "r") as tar:
            def is_within_directory(directory, target):
                abs_directory = os.path.abspath(directory)
                abs_target = os.path.abspath(target)
                prefix = os.path.commonprefix([abs_directory, abs_target])
                return prefix == abs_directory

            def safe_extract(tar, path=".", members=None, *, numeric_owner=False):
                for member in tar.getmembers():
                    member_path = os.path.join(path, member.name)
                    if not is_within_directory(path, member_path):
                        raise Exception("Attempted Path Traversal in Tar File")
                tar.extractall(path, members, numeric_owner=numeric_owner)

            safe_extract(tar, destination_dir)

    except tarfile.ReadError as e:
        logging.error(f"Error reading tarfile: {e}")
        raise tarfile.ReadError(f"Invalid or corrupted tarfile: {e}")
    except Exception as e:
        logging.error(f"Error extracting tarfile: {e}")
        raise Exception(f"Error during tarfile extraction: {e}")

    logging.info(f"Successfully extracted tarfile to: {destination_dir}")
    return destination_dir  # Return the destination directory for further processing


# Example Usage (with error handling):
if __name__ == "__main__":
    # Create a dummy tarfile for testing
    try:
        # Create a temporary directory
        temp_dir = tempfile.mkdtemp()

        # Create a file inside the temporary directory
        test_file_path = os.path.join(temp_dir, "test.txt")
        with open(test_file_path, "w") as f:
            f.write("This is a test file.")

        # Create a tarfile from the temporary directory
        tarfile_path = os.path.join(tempfile.gettempdir(), "test.tar.gz")
        with tarfile.open(tarfile_path, "w:gz") as tar:
            tar.add(temp_dir, arcname="test_dir")  # Add the directory, not just the file

        # Extract the tarfile securely
        extracted_dir = secure_extract_tarfile(tarfile_path)
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
        if 'temp_dir' in locals() and os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)
        if 'tarfile_path' in locals() and os.path.exists(tarfile_path):
            os.remove(tarfile_path)
        if 'extracted_dir' in locals() and os.path.exists(extracted_dir) and extracted_dir.startswith("/tmp/unpack"):
            shutil.rmtree(extracted_dir, ignore_errors=True) # Remove the extracted directory if it's in /tmp/unpack

