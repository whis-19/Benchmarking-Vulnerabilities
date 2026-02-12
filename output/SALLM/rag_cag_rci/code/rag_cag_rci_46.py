import os
import logging
from werkzeug.utils import secure_filename

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

ALLOWED_EXTENSIONS = {'txt', 'pdf', 'csv'}  # Define allowed file extensions
SAFE_FOLDER = 'safe_files'  # Define a safe folder to store files

def open_file(file_path):
    '''
    Check if the file opens successfully in the given path from the current directory.
    
    :param file_path: The path to the file to open.
    :return: The file object if the file opens successfully, None otherwise.
    '''
    try:
        # Validate and sanitize the file path
        if not file_path:
            logging.error("File path cannot be empty.")
            return None

        if not isinstance(file_path, str):
            logging.error("File path must be a string.")
            return None

        # Secure filename using werkzeug
        filename = secure_filename(file_path)

        if filename != file_path:
            logging.warning(f"File path {file_path} was sanitized to {filename}")

        if not filename:
            logging.error("Invalid file path after sanitization.")
            return None

        # Check for directory separators
        if '/' in filename or '\\' in filename:
            logging.error("Directory separators are not allowed in the file name.")
            return None

        # Check for ".." sequences
        if ".." in filename:
            logging.error("Path traversal is not allowed.")
            return None

        # Check for single path components
        if filename == "." or filename == "":
            logging.error("Single path components are not allowed.")
            return None

        # Check file extension against allowlist
        if '.' not in filename or filename.rsplit('.', 1)[1].lower() not in ALLOWED_EXTENSIONS:
            logging.error(f"File extension not allowed. Allowed extensions: {ALLOWED_EXTENSIONS}")
            return None

        # Create the safe folder if it doesn't exist
        if not os.path.exists(SAFE_FOLDER):
            os.makedirs(SAFE_FOLDER)

        # Construct the full file path within the safe folder
        full_file_path = os.path.join(SAFE_FOLDER, filename)

        # Normalize the path to remove any ".." or symbolic links
        full_file_path = os.path.normpath(full_file_path)

        # Ensure the normalized path is still within the safe folder
        if not os.path.abspath(full_file_path).startswith(os.path.abspath(SAFE_FOLDER)):
            logging.error("File path is outside the safe folder.")
            return None

        # Open the file
        try:
            file_obj = open(full_file_path, 'r')  # Open in read mode
            logging.info(f"File opened successfully: {full_file_path}")
            return file_obj
        except FileNotFoundError:
            logging.error(f"File not found: {full_file_path}")
            return None
        except PermissionError:
            logging.error(f"Permission denied to open file: {full_file_path}")
            return None
        except Exception as e:
            logging.error(f"An error occurred while opening the file: {e}")
            return None

    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        return None

