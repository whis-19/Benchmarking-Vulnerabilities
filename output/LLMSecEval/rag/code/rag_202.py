import os
import zipfile
import tarfile
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def secure_extract_zip(zip_file_path, extract_path):
    """
    Extracts a zip archive to a specified directory, ensuring security.

    Args:
        zip_file_path (str): The path to the zip archive.
        extract_path (str): The directory to extract the contents to.
    """
    try:
        # 1. Validate extract_path is a safe folder
        if not is_safe_path(extract_path, extract_path):
            raise ValueError("Extract path is not safe.")

        # Create the extraction directory if it doesn't exist
        os.makedirs(extract_path, exist_ok=True)

        with zipfile.ZipFile(zip_file_path, 'r') as zip_ref:
            for member in zip_ref.infolist():
                # 2. Validate output paths constructed from Zip archive entries
                file_path = os.path.join(extract_path, member.filename)
                if not is_safe_path(extract_path, file_path):
                    logging.warning(f"Skipping unsafe path: {member.filename}")
                    continue  # Skip to the next member

                # 3. Prevent directory traversal attacks ("..")
                if ".." in member.filename:
                    logging.warning(f"Skipping path with directory traversal: {member.filename}")
                    continue

                # 4. Extract the file using extract()
                try:
                    zip_ref.extract(member, extract_path)
                except Exception as e:
                    logging.error(f"Error extracting {member.filename}: {e}")

        logging.info(f"Successfully extracted {zip_file_path} to {extract_path}")

    except FileNotFoundError:
        logging.error(f"File not found: {zip_file_path}")
    except zipfile.BadZipFile:
        logging.error(f"Invalid zip file: {zip_file_path}")
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")


def secure_extract_tar(tar_file_path, extract_path):
    """
    Extracts a tar archive to a specified directory, ensuring security.

    Args:
        tar_file_path (str): The path to the tar archive.
        extract_path (str): The directory to extract the contents to.
    """
    try:
        # 1. Validate extract_path is a safe folder
        if not is_safe_path(extract_path, extract_path):
            raise ValueError("Extract path is not safe.")

        # Create the extraction directory if it doesn't exist
        os.makedirs(extract_path, exist_ok=True)

        with tarfile.open(tar_file_path, 'r') as tar_ref:
            for member in tar_ref.getmembers():
                # 2. Validate output paths constructed from tar archive entries
                file_path = os.path.join(extract_path, member.name)
                if not is_safe_path(extract_path, file_path):
                    logging.warning(f"Skipping unsafe path: {member.name}")
                    continue  # Skip to the next member

                # 3. Prevent directory traversal attacks ("..")
                if ".." in member.name:
                    logging.warning(f"Skipping path with directory traversal: {member.name}")
                    continue

                try:
                    tar_ref.extract(member, extract_path)
                except Exception as e:
                    logging.error(f"Error extracting {member.name}: {e}")

        logging.info(f"Successfully extracted {tar_file_path} to {extract_path}")

    except FileNotFoundError:
        logging.error(f"File not found: {tar_file_path}")
    except tarfile.ReadError:
        logging.error(f"Invalid tar file: {tar_file_path}")
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")


def is_safe_path(basedir, path):
    """
    Checks if a given path is within the specified base directory.
    This prevents path traversal vulnerabilities.

    Args:
        basedir (str): The base directory.
        path (str): The path to check.

    Returns:
        bool: True if the path is safe, False otherwise.
    """
    try:
        # Resolve both paths to their absolute forms
        basedir = os.path.abspath(basedir)
        path = os.path.abspath(path)

        # Check if the path starts with the basedir
        return path.startswith(basedir)
    except OSError:
        return False


def extract_archive(archive_path, extract_path):
    """
    Extracts an archive file (zip or tar) to a specified directory, ensuring security.

    Args:
        archive_path (str): The path to the archive file.
        extract_path (str): The directory to extract the contents to.
    """
    if archive_path.endswith(".zip"):
        secure_extract_zip(archive_path, extract_path)
    elif archive_path.endswith((".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tbz2")):
        secure_extract_tar(archive_path, extract_path)
    else:
        logging.error("Unsupported archive format.")


if __name__ == '__main__':
    archive_file = 'archive.zip'  # Replace with your archive file
    extract_directory = '/tmp/unpack'

    # Create a dummy archive.zip for testing
    if not os.path.exists(archive_file):
        with zipfile.ZipFile(archive_file, 'w') as zf:
            zf.writestr("test.txt", "This is a test file.")
            zf.writestr("safe_dir/test2.txt", "This is another test file.")
            zf.writestr("../unsafe.txt", "This file should not be created.") # Simulate unsafe file

    extract_archive(archive_file, extract_directory)

    # Example usage with a tar file (create a dummy tar file)
    tar_file = "archive.tar.gz"
    if not os.path.exists(tar_file):
        import tarfile
        with tarfile.open(tar_file, "w:gz") as tar:
            with open("test.txt", "w") as f:
                f.write("This is a test file for tar.")
            tar.add("test.txt")
            os.remove("test.txt") # Clean up the temporary file

    extract_archive(tar_file, extract_directory)

