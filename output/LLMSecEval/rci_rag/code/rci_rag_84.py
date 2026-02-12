import base64
import os
import uuid
from PIL import Image, UnidentifiedImageError
import io
import logging
import tempfile

# Configuration -  These should be externalized in a real application
UPLOAD_FOLDER = 'uploads'  # Define the directory to store uploaded images
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}  # Allowed image extensions
MAX_FILE_SIZE = 1024 * 1024 * 5  # 5MB limit
MAX_IMAGE_DIMENSION = 2048 # Maximum width or height of the image
DECOMPRESSION_BOMB_THRESHOLD = 10000000 # Adjust based on server resources

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Custom Exception
class InvalidFileExtensionError(Exception):
    pass

class FileSizeExceededError(Exception):
    pass

class ImageValidationError(Exception):
    pass

class InvalidFileObjectError(Exception):
    pass

class FileReadError(Exception):
    pass

class FileWriteError(Exception):
    pass


def allowed_file(filename):
    """
    Checks if the filename has an allowed extension.
    """
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS if '.' in filename else False

def generate_unique_filename(filename):
    """
    Generates a unique filename with robust sanitization.
    """
    extension = filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''  # Handle no extension
    base_filename = filename.rsplit('.', 1)[0] if '.' in filename else filename
    # Whitelist approach: only allow lowercase letters, numbers, hyphens, and underscores
    safe_chars = "abcdefghijklmnopqrstuvwxyz0123456789-_"
    filename_sanitized = "".join(c for c in base_filename.lower() if c in safe_chars)
    unique_id = uuid.uuid4()
    return f"{filename_sanitized}_{unique_id}.{extension}"  # Add sanitized base filename


def validate_image_content(file, image_data):
    """
    Validates the image content to prevent malicious files.
    Uses Pillow to verify image integrity and dimensions.
    """
    try:
        img = Image.open(io.BytesIO(image_data))
        img.verify()  # Verify that it is indeed an image

        # Check image format matches extension
        try:
            extension = img.format.lower()
        except AttributeError:
            logging.warning(f"Could not determine image format for {file.filename} using img.format.  Assuming invalid.")
            return False, "Could not determine image format."

        filename_extension = file.filename.rsplit('.', 1)[-1].lower() if '.' in file.filename else '' # Assuming 'file' is accessible here
        if extension != filename_extension and filename_extension: # only check if filename has extension
            logging.warning(f"Filename extension {filename_extension} does not match image format {extension} for file {file.filename}")
            # Treat as a warning, but don't definitively reject.  Consider further analysis.
            # For now, just log the mismatch.
            # return False, "Filename extension does not match image format."


        # Check image dimensions
        width, height = img.size
        if width > MAX_IMAGE_DIMENSION or height > MAX_IMAGE_DIMENSION:
            raise ImageValidationError("Image dimensions exceed the maximum allowed.")

        # Check for potential exploits (e.g., decompression bombs)
        if width * height > DECOMPRESSION_BOMB_THRESHOLD: # Adjust this threshold as needed
            raise ImageValidationError("Image is too large to process safely.")

        return True, None  # Image is valid
    except UnidentifiedImageError as e:
        logging.error(f"Unidentified image format for file {file.filename}: {e}")
        raise ImageValidationError("Invalid image format or corrupted file.") from e
    except ImageValidationError as e:
        raise e
    except Exception as e:
        logging.error(f"Image validation error for file {file.filename}: {e}") # Log the error
        raise ImageValidationError("Invalid image format or corrupted file.") from e

def upload_image(file):
    """
    Handles the image upload process.
    """

    if not hasattr(file, 'filename') or not hasattr(file, 'read'):
        logging.error("Invalid file object provided.")
        raise InvalidFileObjectError("Invalid file object provided.")

    if not file:
        raise ValueError("No file provided")

    if not allowed_file(file.filename):
        logging.warning(f"Invalid file extension: {file.filename}")
        raise InvalidFileExtensionError("Invalid file extension. Allowed extensions: " + ", ".join(ALLOWED_EXTENSIONS))

    # Read the file content
    try:
        image_data = file.read()
    except Exception as e:
        logging.error(f"Error reading file {file.filename}: {e}")
        raise FileReadError(f"Error reading file: {e}") from e

    # Check file size
    if len(image_data) > MAX_FILE_SIZE:
        logging.warning(f"File size exceeds maximum allowed: {file.filename}")
        raise FileSizeExceededError("File size exceeds the maximum allowed size.")

    # Validate image content
    try:
        is_valid, error_message = validate_image_content(file, image_data)
        if not is_valid:
            raise ImageValidationError(error_message)
    except ImageValidationError as e:
        logging.warning(f"Image validation failed for {file.filename}: {e}")
        raise

    # Generate a unique filename
    filename = generate_unique_filename(file.filename)
    filepath = os.path.join(UPLOAD_FOLDER, filename)

    # Ensure the upload directory exists
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    UPLOAD_FOLDER_ABS = os.path.abspath(UPLOAD_FOLDER) # Ensure absolute path

    # Write the image data to the file
    try:
        with open(filepath, 'wb') as f:  # Open in binary write mode
            f.write(image_data)
    except Exception as e:
        logging.error(f"Error writing file {file.filename} to disk: {e}")
        raise FileWriteError(f"Error writing file: {e}") from e

    logging.info(f"Image uploaded successfully to {filepath}")
    return f"Image uploaded successfully to {filepath}", 200

if __name__ == '__main__':
    # Example usage (replace with your actual file upload mechanism)
    # This is just a simulation for testing purposes.  In a real application,
    # you'd get the file from a web framework like Flask or Django.

    # Create a temporary directory for test files
    with tempfile.TemporaryDirectory() as temp_dir:
        test_image_path = os.path.join(temp_dir, "test_image.png")

        # Create a dummy image file for testing
        with open(test_image_path, "wb") as f:
            # Create a small, valid PNG image
            f.write(base64.b64decode("iVBORw0KGgoAAAANSUhEUgAAAAUAAAAFCAYAAACNbyblAAAAHElEQVQI12P4//8/w+rAI0wQDA4M7wJiMAMMQIEGAAN2BQ+nByYPAAAAAElFTkSuQmCC"))

        class MockFile:
            def __init__(self, filename, content):
                self.filename = filename
                self.content = content

            def read(self):
                return self.content

        with open(test_image_path, "rb") as f:
            test_file_content = f.read()
        mock_file = MockFile("test_image.png", test_file_content)

        try:
            message, status_code = upload_image(mock_file)
            print(f"Upload result: {message}, Status: {status_code}")
        except (InvalidFileExtensionError, FileSizeExceededError, ImageValidationError, InvalidFileObjectError, FileReadError, FileWriteError) as e:
            print(f"Upload failed: {e}")

        # No need to clean up, the temporary directory is automatically removed

