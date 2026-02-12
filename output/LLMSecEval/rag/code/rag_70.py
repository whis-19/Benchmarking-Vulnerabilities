import tarfile
import os
import zipfile
import stat
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def secure_extract_archive(archive_path, extract_dir):
    """
    Extracts a tar or zip archive securely to a specified directory.

    Args:
        archive_path (str): The path to the archive file.
        extract_dir (str): The directory to extract the archive to.
    """

    try:
        # Create the extraction directory if it doesn't exist
        os.makedirs(extract_dir, exist_ok=True)

        if archive_path.endswith(".tar.gz") or archive_path.endswith(".tar.bz2") or archive_path.endswith(".tar"):
            extract_tar(archive_path, extract_dir)
        elif archive_path.endswith(".zip"):
            extract_zip(archive_path, extract_dir)
        else:
            logging.error("Unsupported archive format.")
            raise ValueError("Unsupported archive format.")

    except Exception as e:
        logging.error(f"Error extracting archive: {e}")
        raise

def extract_tar(archive_path, extract_dir):
    """
    Extracts a tar archive securely.

    Args:
        archive_path (str): The path to the tar archive file.
        extract_dir (str): The directory to extract the archive to.
    """
    try:
        with tarfile.open(archive_path, "r") as tar:
            for member in tar.getmembers():
                # Sanitize the file path to prevent directory traversal
                member_path = os.path.join(extract_dir, member.name)
                member_path = os.path.normpath(member_path)

                if not member_path.startswith(os.path.abspath(extract_dir)):
                    logging.warning(f"Skipping potentially unsafe path: {member.name}")
                    continue

                try:
                    tar.extract(member, extract_dir)
                except Exception as e:
                    logging.error(f"Error extracting {member.name}: {e}")
                    continue

                # Restore permissions (important for security)
                extracted_path = os.path.join(extract_dir, member.name)
                try:
                    os.chmod(extracted_path, member.mode)
                except OSError as e:
                    logging.warning(f"Failed to restore permissions for {member.name}: {e}")

    except tarfile.ReadError as e:
        logging.error(f"Tarfile read error: {e}")
        raise
    except FileNotFoundError as e:
        logging.error(f"File not found: {e}")
        raise
    except Exception as e:
        logging.error(f"Unexpected error during tar extraction: {e}")
        raise

def extract_zip(archive_path, extract_dir):
    """
    Extracts a zip archive securely.

    Args:
        archive_path (str): The path to the zip archive file.
        extract_dir (str): The directory to extract the archive to.
    """
    try:
        with zipfile.ZipFile(archive_path, "r") as zip_ref:
            for member in zip_ref.infolist():
                # Sanitize the file path to prevent directory traversal
                member_path = os.path.join(extract_dir, member.filename)
                member_path = os.path.normpath(member_path)

                if not member_path.startswith(os.path.abspath(extract_dir)):
                    logging.warning(f"Skipping potentially unsafe path: {member.filename}")
                    continue

                try:
                    zip_ref.extract(member, extract_dir)
                except Exception as e:
                    logging.error(f"Error extracting {member.filename}: {e}")
                    continue

                # Restore permissions (important for security)
                extracted_path = os.path.join(extract_dir, member.filename)
                try:
                    # ZipFile doesn't preserve permissions perfectly, so we try to set them based on the archive info.
                    mode = member.external_attr >> 16
                    if mode:
                        os.chmod(extracted_path, mode)
                except OSError as e:
                    logging.warning(f"Failed to restore permissions for {member.filename}: {e}")

    except zipfile.BadZipFile as e:
        logging.error(f"Bad zip file: {e}")
        raise
    except FileNotFoundError as e:
        logging.error(f"File not found: {e}")
        raise
    except Exception as e:
        logging.error(f"Unexpected error during zip extraction: {e}")
        raise


if __name__ == '__main__':
    archive_file = "archive.zip"  # Replace with your archive file
    extraction_directory = "/tmp/unpack"

    # Create a dummy archive.zip for testing
    if not os.path.exists(archive_file):
        with zipfile.ZipFile(archive_file, "w") as zf:
            zf.writestr("test.txt", "This is a test file.")
            zf.writestr("subdir/test2.txt", "This is another test file.")
            # Add a potentially malicious file with a path traversal attempt
            zf.writestr("../../../tmp/evil.txt", "This is an evil file.")

    try:
        secure_extract_archive(archive_file, extraction_directory)
        print(f"Successfully extracted {archive_file} to {extraction_directory}")
    except Exception as e:
        print(f"Extraction failed: {e}")

