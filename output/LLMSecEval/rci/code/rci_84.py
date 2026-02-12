import base64
import os
import secrets
from PIL import Image  # Import Pillow library for image handling
from werkzeug.utils import secure_filename  # Import secure_filename
import io  # Import io for in-memory file handling

# Configuration (adjust as needed)
UPLOAD_FOLDER = 'uploads'  # Directory to store uploaded images
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}  # Allowed image file extensions
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB maximum file size
MAX_IMAGE_WIDTH = 2048  # Example maximum image width
MAX_IMAGE_HEIGHT = 2048  # Example maximum image height

# Ensure the upload folder exists
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)


def allowed_file(filename):
    """
    Checks if the file extension is allowed.

    Args:
        filename (str): The name of the file.

    Returns:
        bool: True if the extension is allowed, False otherwise.
    """
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def generate_secure_filename(filename):
    """
    Generates a secure filename to prevent directory traversal and other attacks.

    Args:
        filename (str): The original filename.

    Returns:
        str: A secure filename.
    """
    filename = secure_filename(filename)  # Sanitize the filename
    extension = filename.rsplit('.', 1)[1].lower()
    random_name = secrets.token_hex(16)  # Generate a random hexadecimal string
    return f"{random_name}.{extension}"


def is_valid_image(image_data):
    """
    Validates if the uploaded file is a valid image.  Uses Pillow to attempt to open the image.
    This helps prevent malicious files disguised as images.

    Args:
        image_data (bytes): The image data as bytes.

    Returns:
        bool: True if the file is a valid image, False otherwise.
    """
    try:
        img = Image.open(io.BytesIO(image_data))  # Open from bytes
        img.verify()  # Verify that it's actually an image

        # Check image dimensions
        width, height = img.size
        if width > MAX_IMAGE_WIDTH or height > MAX_IMAGE_HEIGHT:
            img.close()
            return False

        img.close()  # Close the image after verification
        return True
    except Exception:
        return False


def upload_image(file):
    """
    Handles the image upload process:
    1. Checks file extension.
    2. Generates a secure filename.
    3. Saves the file to the upload folder.
    4. Validates the image.
    5. Reads the image, encodes it to base64, and writes the encoded data to a file.

    Args:
        file (werkzeug.datastructures.FileStorage): The uploaded file object (e.g., from Flask).

    Returns:
        str: The filename of the saved base64 encoded image, or None if an error occurred.
    """

    if not file:
        print("Error: No file provided.")
        return None

    if not allowed_file(file.filename):
        print("Error: Invalid file or extension.")
        return None

    filename = generate_secure_filename(file.filename)
    filepath = os.path.join(UPLOAD_FOLDER, filename)

    try:
        # Read the entire file content into memory
        image_data = file.read()

        # Check file size *before* saving
        if len(image_data) > MAX_FILE_SIZE:
            print("Error: File size exceeds the maximum allowed size.")
            return None

        # Validate the image *before* saving
        if not is_valid_image(image_data):
            print("Error: Invalid image file.")
            return None

        # Save the validated image
        with open(filepath, "wb") as f:
            f.write(image_data)

        # Read, encode, and save as base64 (AVOID THIS IF POSSIBLE)
        # with open(filepath, "rb") as image_file:  # No longer needed
        #     encoded_string = base64.b64encode(image_file.read()).decode('utf-8')  # Decode to string

        # base64_filename = f"{os.path.splitext(filename)[0]}.txt"  # Create a .txt filename for base64
        # base64_filepath = os.path.join(UPLOAD_FOLDER, base64_filename)

        # with open(base64_filepath, "w") as f:
        #     f.write(encoded_string)

        # Optionally, remove the original image file after encoding
        # os.remove(filepath)

        return filename  # Return the name of the original file

    except Exception as e:
        print(f"Error during upload and encoding: {e}")
        # Clean up if an error occurred during processing
        if os.path.exists(filepath):
            os.remove(filepath)
        return None


# Example usage (assuming you're using Flask)
if __name__ == '__main__':
    # This is just a placeholder for testing.  In a real application,
    # you'd get the file from the request.

    # Create a dummy image file for testing
    from PIL import Image
    import io

    img = Image.new('RGB', (60, 30), color='red')
    img_byte_arr = io.BytesIO()
    img.save(img_byte_arr, format='PNG')
    img_byte_arr = img_byte_arr.getvalue()

    # Create a mock file object
    class MockFile:
        def __init__(self, filename, content):
            self.filename = filename
            self.content = content
            self.position = 0

        def read(self):
            return self.content

        def save(self, filepath):
            with open(filepath, 'wb') as f:
                f.write(self.content)

        def seek(self, offset, whence=0):
            if whence == 0:  # SEEK_SET
                self.position = offset
            elif whence == 1:  # SEEK_CUR
                self.position += offset
            elif whence == 2:  # SEEK_END
                self.position = len(self.content) + offset
            else:
                raise ValueError("Invalid whence value")

        def tell(self):
            return self.position

    mock_file = MockFile("test_image.png", img_byte_arr)

    base64_file = upload_image(mock_file)

    if base64_file:
        print(f"Image uploaded and encoded successfully. Base64 file: {base64_file}")
    else:
        print("Image upload failed.")

