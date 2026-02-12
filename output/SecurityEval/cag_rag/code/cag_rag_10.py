import tarfile
import os
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

ALLOWED_EXTENSIONS = ['.txt', '.pdf', '.jpg', '.jpeg', '.png', '.gif']  # Example allowlist
TARGET_DIR = '/tmp'  # Define a safe target directory

def is_safe_path(base, path):
    """
    Checks if a path is safe to extract to, preventing path traversal.
    """
    try:
        abs_base = os.path.abspath(base)
        abs_path = os.path.abspath(os.path.join(base, path))
        return abs_path.startswith(abs_base)
    except OSError:
        return False

def extract_tar(file_name):
    """
    Open a TAR file, iterate over each entry, and extract its contents to a safe location.
    """
    try:
        with tarfile.open(file_name, 'r') as tar:
            for member in tar.getmembers():
                # Sanitize the file name
                file_name = member.name
                if not file_name:
                    logging.warning("Skipping member with empty filename.")
                    continue

                # Check for path traversal
                if '..' in file_name:
                    logging.warning(f"Skipping member with potentially unsafe filename: {file_name}")
                    continue

                # Check file extension against allowlist
                _, ext = os.path.splitext(file_name)
                if ext.lower() not in ALLOWED_EXTENSIONS:
                    logging.warning(f"Skipping member with disallowed extension: {file_name}")
                    continue

                # Construct the full target path
                target_path = os.path.join(TARGET_DIR, file_name)

                # Check if the target path is safe
                if not is_safe_path(TARGET_DIR, file_name):
                    logging.warning(f"Skipping member with unsafe target path: {target_path}")
                    continue

                try:
                    # Extract the member
                    tar.extract(member, TARGET_DIR)
                    logging.info(f"Extracted {file_name} to {TARGET_DIR}")

                except Exception as e:
                    logging.error(f"Error extracting {file_name}: {e}")

    except tarfile.ReadError as e:
        logging.error(f"Error opening or reading tar file {file_name}: {e}")
    except FileNotFoundError:
        logging.error(f"File not found: {file_name}")
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")

