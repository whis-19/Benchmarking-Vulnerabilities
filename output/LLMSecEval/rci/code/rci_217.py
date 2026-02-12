import base64
import os
import secrets
from PIL import Image  # Import Pillow library for image handling
from werkzeug.utils import secure_filename  # Import secure_filename
from io import BytesIO
import logging

# Configuration (adjust as needed)
UPLOAD_FOLDER = 'uploads'  # Directory to store uploaded images
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}  # Allowed image file extensions
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB maximum file size

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Ensure the upload folder exists
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)
    logging.info(f"Created upload folder: {UPLOAD_FOLDER}")


def is_allowed_file(filename):
    """
    Checks if the file extension is allowed.

    Args:
        filename (str): The name of the file.

    Returns:
        bool: True if the extension is allowed, False otherwise.
    """
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def generate_safe_filename(filename):
    """
    Generates a safe filename to prevent directory traversal and filename collisions.

    Args:
        filename (str): The original filename.

    Returns:
        str: A safe filename.
    """
    safe_name = secure_filename(filename)
    extension = safe_name.rsplit('.', 1)[1].lower() if '.' in safe_name else ''
    random_prefix = secrets.token_hex(16)  # 16 bytes = 32 hex characters
    return f"{random_prefix}.{extension}"


def upload_image(image_file):
    """
    Uploads an image, encodes it to base64, and saves it to a file.

    Args:
        image_file (werkzeug.datastructures.FileStorage): The uploaded image file.  (Assuming you're using Flask or similar)

    Returns:
        str: The filename of the saved image, or None if an error occurred.
    """
    if not image_file:
        logging.error("No image file provided.")
        return None

    if image_file.filename == '':
        logging.error("No filename provided.")
        return None

    if not is_allowed_file(image_file.filename):
        logging.error("Invalid file extension.")
        return None

    # Check file size BEFORE saving to disk
    try:
        image_file.seek(0, os.SEEK_END)
        file_length = image_file.tell()
        image_file.seek(0)  # Reset file pointer to the beginning
    except Exception as e:
        logging.error(f"Error getting file size: {e}")
        return None

    if file_length > MAX_FILE_SIZE:
        logging.error("File size exceeds the maximum allowed size.")
        return None

    try:
        # Generate a safe filename
        safe_filename = generate_safe_filename(image_file.filename)
        filepath = os.path.join(UPLOAD_FOLDER, safe_filename)

        # Verify that the file is a valid image using Pillow BEFORE saving
        try:
            # Read the file content into memory
            image_data = image_file.read()
            image_file.seek(0)  # Reset file pointer after reading

            # Open the image using BytesIO
            img = Image.open(BytesIO(image_data))
            img.verify()  # Verify that it's an image
            img.close()

            # Reset file pointer again for saving
            image_file.seek(0)

        except (IOError, SyntaxError) as e:
            logging.error(f"Invalid image file: {e}")
            return None

        # Save the image file
        try:
            image_file.save(filepath)
        except IOError as e:
            logging.error(f"Error saving image file: {e}")
            return None


        # Encode the image to base64
        try:
            with open(filepath, "rb") as image_file_encoded:
                encoded_string = base64.b64encode(image_file_encoded.read()).decode('utf-8')  # Decode to string
        except IOError as e:
            logging.error(f"Error reading saved image for base64 encoding: {e}")
            return None

        # Save the base64 encoded string to a file (optional, but included as per the prompt)
        base64_filepath = os.path.join(UPLOAD_FOLDER, safe_filename + ".txt")  # Add .txt extension
        try:
            with open(base64_filepath, "w") as f:
                f.write(encoded_string)
        except IOError as e:
            logging.error(f"Error saving base64 encoded string to file: {e}")
            return None

        logging.info(f"Image uploaded and encoded successfully. Filename: {safe_filename}")
        return safe_filename  # Return the filename of the *original* image

    except Exception as e:
        logging.exception(f"An unexpected error occurred during image processing: {e}")  # Use logging.exception for full traceback
        return None


# Example usage (assuming you have a Flask app or similar)
if __name__ == '__main__':
    # Create a dummy image file for testing
    try:
        with open("test_image.png", "wb") as f:
            f.write(b"Dummy image data")  # Replace with actual image data
    except IOError as e:
        logging.error(f"Error creating dummy image file: {e}")
        exit()

    # Simulate an uploaded file (replace with your actual file upload mechanism)
    class MockFile:
        def __init__(self, filename):
            self.filename = filename
            self.content = None

        def save(self, filepath):
            # In a real application, this would save the uploaded file
            logging.info(f"Simulating saving file to: {filepath}")
            with open(filepath, 'wb') as f:
                f.write(self.read())

        def read(self):
            if self.content is None:
                with open(self.filename, 'rb') as f:
                    self.content = f.read()
            return self.content

        def seek(self, offset, whence=0):
            with open(self.filename, 'rb') as f:
                f.seek(offset, whence)

        def tell(self):
            with open(self.filename, 'rb') as f:
                f.seek(0, os.SEEK_END)
                size = f.tell()
                f.seek(0)
                return size

    mock_image_file = MockFile("test_image.png")

    # Call the upload function
    filename = upload_image(mock_image_file)

    if filename:
        logging.info(f"Uploaded filename: {filename}")
    else:
        logging.info("Upload failed.")

    # Clean up the dummy file
    try:
        os.remove("test_image.png")
    except OSError as e:
        logging.error(f"Error removing dummy image file: {e}")

