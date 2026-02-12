import os
import base64
import uuid
from PIL import Image
import io

# Configuration -  These should be externalized in a real application
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB limit
MAX_IMAGE_DIMENSION = 2048 # Maximum width or height in pixels
# Ensure the upload folder exists
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)


def allowed_file(filename):
    """
    Checks if the filename has an allowed extension.
    Also ensures there's only one extension.
    """
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS and \
           filename.count('.') == 1


def validate_image_content(file_content):
    """
    Validates the image content to prevent malicious files.
    Uses Pillow to attempt to open the image and check its dimensions.
    """
    try:
        img = Image.open(io.BytesIO(file_content))
        img.verify()  # Verify that it is actually an image
        img = Image.open(io.BytesIO(file_content)) # Reload image after verify
        width, height = img.size
        if width > MAX_IMAGE_DIMENSION or height > MAX_IMAGE_DIMENSION:
            return False, "Image dimensions exceed maximum allowed size."
        return True, None
    except Exception as e:
        print(f"Image validation error: {e}")  # Log the error
        return False, "Invalid image format or corrupted file."


def upload_image(file_storage):
    """
    Handles the image upload process securely.

    Args:
        file_storage:  A file-like object representing the uploaded image.  This would typically come from a web framework like Flask or Django.

    Returns:
        A tuple: (success, message, filename (if successful))
    """

    if file_storage is None:
        return False, "No file provided.", None

    filename = file_storage.filename
    if not allowed_file(filename):
        return False, "Invalid file extension. Allowed extensions are: " + ", ".join(ALLOWED_EXTENSIONS), None

    file_content = file_storage.read()

    if len(file_content) > MAX_FILE_SIZE:
        return False, "File size exceeds the maximum allowed size.", None

    # Validate image content
    is_valid, validation_message = validate_image_content(file_content)
    if not is_valid:
        return False, validation_message, None

    # Generate a unique filename
    unique_filename = str(uuid.uuid4()) + "." + filename.rsplit('.', 1)[1].lower()
    filepath = os.path.join(UPLOAD_FOLDER, unique_filename)

    try:
        # Write the file in binary mode
        with open(filepath, 'wb') as f:
            f.write(file_content)

        return True, "Image uploaded successfully.", unique_filename

    except Exception as e:
        print(f"File writing error: {e}") # Log the error
        return False, "Failed to save the image.", None


# Example usage (assuming you have a file-like object named 'image_file'):
if __name__ == '__main__':
    # Create a dummy image file for testing
    with open("test_image.png", "wb") as f:
        # Create a small, valid PNG image
        f.write(base64.b64decode("iVBORw0KGgoAAAANSUhEUgAAAAUAAAAFCAYAAACNbyblAAAAHElEQVQI12P4//8/w+gYBsAAwAAAZ4QY1wAAAABJRU5ErkJggg=="))

    class MockFileStorage:
        def __init__(self, filename, content):
            self.filename = filename
            self.content = content

        def read(self):
            return self.content

    with open("test_image.png", "rb") as f:
        image_file = MockFileStorage("test_image.png", f.read())

    success, message, filename = upload_image(image_file)

    if success:
        print(f"Upload successful! Filename: {filename}")
    else:
        print(f"Upload failed: {message}")

    # Clean up the test file
    os.remove("test_image.png")
    if filename:
        os.remove(os.path.join(UPLOAD_FOLDER, filename))

