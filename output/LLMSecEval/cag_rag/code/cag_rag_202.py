import zipfile
import os
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def secure_extract_zip(zip_file_path, extract_path):
    """
    Securely extracts a zip file to a specified directory.

    Args:
        zip_file_path (str): The path to the zip file.
        extract_path (str): The directory to extract the contents to.
    """

    # Security guideline 1, 10, 11, 12, 13: Validate and sanitize file paths
    if not isinstance(zip_file_path, str) or not isinstance(extract_path, str):
        raise TypeError("File paths must be strings.")

    if ".." in zip_file_path or "/" in zip_file_path or "\\" in zip_file_path:
        raise ValueError("Invalid characters in zip file path.")

    if ".." in extract_path or "/" in extract_path or "\\" in extract_path:
        raise ValueError("Invalid characters in extract path.")

    # Define a safe base directory
    safe_base_dir = "/tmp"  # Example safe directory

    # Check if the extract path is within the safe base directory
    if not os.path.abspath(extract_path).startswith(safe_base_dir):
        raise ValueError("Extract path is not within the safe base directory.")

    # Security guideline 2: Prevent path traversal attacks
    if not os.path.exists(extract_path):
        try:
            os.makedirs(extract_path, exist_ok=True)  # Create the directory if it doesn't exist
        except OSError as e:
            logging.error(f"Failed to create directory {extract_path}: {e}")
            raise

    try:
        with zipfile.ZipFile(zip_file_path, 'r') as zip_ref:
            for member in zip_ref.infolist():
                # Validate output path for each member
                file_path = os.path.join(extract_path, member.filename)

                # Security guideline 6, 7: Prevent path traversal
                if ".." in member.filename:
                    logging.warning(f"Skipping entry {member.filename} due to path traversal risk.")
                    continue

                # Security guideline 11: Ensure filepath is contained within a safe folder
                abs_path = os.path.abspath(file_path)
                if not abs_path.startswith(os.path.abspath(extract_path)):
                    logging.warning(f"Skipping entry {member.filename} as it extracts outside the target directory.")
                    continue

                # Security guideline 8: Use extract() or extractall()
                try:
                    zip_ref.extract(member, extract_path)
                except Exception as e:
                    logging.error(f"Failed to extract {member.filename}: {e}")
                    continue

                # Security guideline 4: Implement proper file permissions and access controls
                # Example: Set file permissions to read/write for the owner only
                try:
                    os.chmod(file_path, 0o600)
                except OSError as e:
                    logging.warning(f"Failed to set permissions for {file_path}: {e}")

        logging.info(f"Successfully extracted {zip_file_path} to {extract_path}")

    except zipfile.BadZipFile:
        logging.error(f"Invalid zip file: {zip_file_path}")
        raise
    except FileNotFoundError:
        logging.error(f"Zip file not found: {zip_file_path}")
        raise
    except Exception as e:
        logging.error(f"An error occurred: {e}")
        raise

# Example usage:
if __name__ == '__main__':
    zip_file = 'archive.zip'  # Replace with the actual path to your zip file
    extract_dir = '/tmp/unpack'

    # Create a dummy zip file for testing
    if not os.path.exists(zip_file):
        with zipfile.ZipFile(zip_file, 'w') as zf:
            zf.writestr("test.txt", "This is a test file.")
            zf.writestr("subdir/test2.txt", "This is another test file.")

    try:
        secure_extract_zip(zip_file, extract_dir)
    except ValueError as e:
        print(f"Error: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

