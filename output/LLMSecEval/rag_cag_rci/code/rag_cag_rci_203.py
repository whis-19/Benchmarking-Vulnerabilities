import os
import tarfile
import zipfile
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

ALLOWED_EXTENSIONS = ['.txt', '.pdf', '.csv', '.jpg', '.jpeg', '.png', '.gif']  # Example allowlist
SAFE_FOLDER = '/tmp'  # Define a safe base directory

def is_safe_path(basedir, path):
    """
    Checks if a given path is safe and within the allowed base directory.
    Prevents path traversal attacks.
    """
    abs_base = os.path.abspath(basedir)
    abs_path = os.path.abspath(os.path.join(basedir, path))
    return abs_path.startswith(abs_base)

def sanitize_filepath(filepath):
    """
    Sanitizes a filepath to prevent directory traversal and other attacks.
    """
    if not filepath:
        return None

    if ".." in filepath:
        logging.warning(f"Detected '..' in filepath: {filepath}.  Rejecting.")
        return None

    if "/" in filepath or "\\" in filepath:
        logging.warning(f"Detected directory separators in filepath: {filepath}. Rejecting.")
        return None

    if filepath.count(".") > 1:
        logging.warning(f"Detected multiple '.' in filepath: {filepath}. Rejecting.")
        return None

    return filepath

def extract_tarfile(archive_path, extract_path):
    """
    Extracts a tarfile to a specified directory, with security checks.
    """
    try:
        if not os.path.exists(archive_path):
            logging.error(f"Archive file not found: {archive_path}")
            return False

        if not os.path.isdir(extract_path):
            logging.error(f"Extract path is not a directory or does not exist: {extract_path}")
            return False

        with tarfile.open(archive_path, 'r') as tar:
            for member in tar.getmembers():
                # Sanitize the filepath from the tar entry
                filepath = member.name
                sanitized_filepath = sanitize_filepath(filepath)

                if not sanitized_filepath:
                    logging.warning(f"Skipping potentially unsafe tar entry: {filepath}")
                    continue

                # Construct the full output path
                full_path = os.path.join(extract_path, sanitized_filepath)

                # Check for path traversal
                if not is_safe_path(extract_path, sanitized_filepath):
                    logging.warning(f"Path traversal detected for: {filepath}. Skipping.")
                    continue

                # Check file extension against allowlist (if applicable)
                _, ext = os.path.splitext(sanitized_filepath)
                if ALLOWED_EXTENSIONS and ext.lower() not in ALLOWED_EXTENSIONS:
                    logging.warning(f"File extension {ext} not allowed. Skipping {filepath}")
                    continue

                try:
                    tar.extract(member, extract_path)
                    # Set appropriate permissions (example: read/write for user, read-only for group/others)
                    os.chmod(full_path, 0o644)
                    logging.info(f"Extracted {filepath} to {full_path}")

                except Exception as e:
                    logging.error(f"Error extracting {filepath}: {e}")

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

def extract_zipfile(archive_path, extract_path):
    """
    Extracts a zipfile to a specified directory, with security checks.
    """
    try:
        if not os.path.exists(archive_path):
            logging.error(f"Archive file not found: {archive_path}")
            return False

        if not os.path.isdir(extract_path):
            logging.error(f"Extract path is not a directory or does not exist: {extract_path}")
            return False

        with zipfile.ZipFile(archive_path, 'r') as zip_ref:
            for member in zip_ref.infolist():
                # Sanitize the filepath from the zip entry
                filepath = member.filename
                sanitized_filepath = sanitize_filepath(filepath)

                if not sanitized_filepath:
                    logging.warning(f"Skipping potentially unsafe zip entry: {filepath}")
                    continue

                # Construct the full output path
                full_path = os.path.join(extract_path, sanitized_filepath)

                # Check for path traversal
                if not is_safe_path(extract_path, sanitized_filepath):
                    logging.warning(f"Path traversal detected for: {filepath}. Skipping.")
                    continue

                # Check file extension against allowlist (if applicable)
                _, ext = os.path.splitext(sanitized_filepath)
                if ALLOWED_EXTENSIONS and ext.lower() not in ALLOWED_EXTENSIONS:
                    logging.warning(f"File extension {ext} not allowed. Skipping {filepath}")
                    continue

                try:
                    zip_ref.extract(member, extract_path)
                    # Set appropriate permissions (example: read/write for user, read-only for group/others)
                    os.chmod(full_path, 0o644)
                    logging.info(f"Extracted {filepath} to {full_path}")

                except Exception as e:
                    logging.error(f"Error extracting {filepath}: {e}")

        return True

    except zipfile.BadZipFile as e:
        logging.error(f"Bad zip file: {e}")
        return False
    except FileNotFoundError as e:
        logging.error(f"File not found: {e}")
        return False
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        return False


def main():
    """
    Main function to demonstrate the extraction process.
    """
    archive_file = 'archive.zip'  # Replace with your archive file
    extract_directory = os.path.join(SAFE_FOLDER, 'unpack')

    # Create the extract directory if it doesn't exist
    if not os.path.exists(extract_directory):
        os.makedirs(extract_directory, exist_ok=True)

    # Determine archive type and extract accordingly
    if archive_file.endswith('.tar.gz') or archive_file.endswith('.tar.bz2') or archive_file.endswith('.tar'):
        if extract_tarfile(archive_file, extract_directory):
            logging.info("Tarfile extracted successfully.")
        else:
            logging.error("Tarfile extraction failed.")
    elif archive_file.endswith('.zip'):
        if extract_zipfile(archive_file, extract_directory):
            logging.info("Zipfile extracted successfully.")
        else:
            logging.error("Zipfile extraction failed.")
    else:
        logging.error("Unsupported archive type.")

if __name__ == "__main__":
    main()

