import zipfile
import os
import stat
import logging

logging.basicConfig(level=logging.INFO)

def secure_extract_zip(zip_file_path, extract_path):
    """
    Extracts a zip archive securely to a specified directory.

    Args:
        zip_file_path (str): The path to the zip archive.
        extract_path (str): The directory to extract the contents to.
    """

    try:
        # Create the extraction directory if it doesn't exist
        os.makedirs(extract_path, exist_ok=True)

        with zipfile.ZipFile(zip_file_path, 'r') as zip_ref:
            for member in zip_ref.infolist():
                # Construct the full path to the extracted file
                file_path = os.path.join(extract_path, member.filename)

                # Validate the path to prevent directory traversal vulnerabilities
                abs_file_path = os.path.abspath(file_path)
                abs_extract_path = os.path.abspath(extract_path)

                if not abs_file_path.startswith(abs_extract_path):
                    logging.error(f"Attempted to extract to invalid path: {file_path}")
                    continue  # Skip to the next file

                # Prevent ".." in the path
                if ".." in member.filename:
                    logging.error(f"Attempted to extract file with '..' in the path: {member.filename}")
                    continue

                try:
                    zip_ref.extract(member, extract_path)

                    # Restore permissions (if available)
                    if member.external_attr != 0:
                        os.chmod(file_path, member.external_attr >> 16)

                except Exception as e:
                    logging.error(f"Error extracting {member.filename}: {e}")

    except FileNotFoundError:
        logging.error(f"Zip file not found: {zip_file_path}")
    except zipfile.BadZipFile:
        logging.error(f"Invalid zip file: {zip_file_path}")
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")


if __name__ == '__main__':
    # Example usage:
    zip_file = "archive.zip"  # Replace with your zip file
    extract_dir = "/tmp/unpack"

    # Create a dummy zip file for testing
    if not os.path.exists(zip_file):
        with zipfile.ZipFile(zip_file, 'w') as zf:
            zf.writestr("test.txt", "This is a test file.")
            zf.writestr("subdir/test2.txt", "This is another test file.")
            # Add a file with a potentially dangerous path
            # zf.writestr("../outside.txt", "This should not be extracted.") # Removed for security reasons

    secure_extract_zip(zip_file, extract_dir)
    print(f"Successfully extracted {zip_file} to {extract_dir}")

