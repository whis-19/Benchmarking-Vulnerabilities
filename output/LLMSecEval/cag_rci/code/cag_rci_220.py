import os
import uuid
from pathlib import Path
from typing import Tuple
import logging
import magic  # Import the python-magic library

logging.basicConfig(filename='upload_errors.log', level=logging.INFO)  # More verbose logging

ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}
UPLOAD_FOLDER = 'uploads'
MAX_FILE_SIZE = 10 * 1024 * 1024

# Add a deny list for particularly dangerous extensions
DENIED_EXTENSIONS = {'php', 'exe', 'sh', 'bat', 'ps1'}


def is_allowed_file(filename: str) -> bool:
    """
    Checks if the file extension is allowed.
    """
    if '.' not in filename:
        return False

    extension = filename.rsplit('.', 1)[1].lower()
    if not extension:  # Check for empty extension
        return False
    return extension in ALLOWED_EXTENSIONS and extension not in DENIED_EXTENSIONS


def validate_content_type(file_content, filename: str) -> bool:
    """
    Validates the file content type using python-magic.
    """
    try:
        mime = magic.from_buffer(file_content, mime=True).decode('utf-8')
        logging.info(f"Detected MIME type: {mime} for file: {filename}") # Log the detected MIME type

        # Example: Allow only image types
        if not mime.startswith('image/'):
            logging.warning(f"Content type validation failed for {filename}: {mime}")
            return False
        return True
    except magic.MagicException as e:
        logging.error(f"Error during content type validation for {filename}: {e}")
        return False
    except Exception as e:
        logging.exception(f"Unexpected error during content type validation for {filename}:")  # Log traceback
        return False


def upload_file(file_storage, filename: str) -> Tuple[bool, str]:
    """
    Handles the upload of a file, performing security checks and saving it to the upload folder.
    """

    try:
        # 1. Validate file extension
        if not is_allowed_file(filename):
            logging.warning(f"File extension validation failed for {filename}")
            return False, "Error: Invalid file extension."

        # 2. Generate a safe filename
        safe_filename = generate_safe_filename(filename)

        # 3. Create the upload directory if it doesn't exist
        create_upload_directory(UPLOAD_FOLDER)

        # 4. Construct the full, safe file path
        filepath = Path(UPLOAD_FOLDER) / safe_filename

        # 5. Read file content
        file_content = file_storage.read()

        # 6. Validate file size
        if not validate_file_size(file_content):
            logging.warning(f"File size validation failed for {filename}")
            return False, "Error: File size exceeds the maximum allowed size."

        # 7. Validate content type
        if not validate_content_type(file_content, filename):
            return False, "Error: Invalid file content type."

        # 8. Save the file (using atomic operation)
        try:
            temp_filepath = filepath.with_suffix(".tmp")  # Create a temporary file
            with open(temp_filepath, "wb") as f:
                f.write(file_content)
            os.chmod(temp_filepath, 0o640)
            os.replace(temp_filepath, filepath)  # Atomic rename
            #os.chmod(filepath, 0o640) # Not needed after os.replace
        except OSError as e:
            logging.exception(f"Error saving file: {e}")  # Log the full exception
            return False, "Error saving file."

        logging.info(f"File uploaded successfully: {safe_filename}") # Log successful upload
        return True, "File uploaded successfully."

    except Exception as e:
        logging.exception("Error during file upload:")  # Log the full exception
        return False, "An unexpected error occurred during file upload. Please try again later."

