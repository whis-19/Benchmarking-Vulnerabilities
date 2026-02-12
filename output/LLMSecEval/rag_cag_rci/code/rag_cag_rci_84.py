import base64
import os
from werkzeug.utils import secure_filename

UPLOAD_FOLDER = 'uploads'  # Define a safe upload folder
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}  # Define allowed file extensions

def allowed_file(filename):
    """
    Checks if the file extension is allowed.
    """
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def upload_image(image_data, filename):
    """
    Uploads an image, encodes it using base64, and writes it to a file.

    Args:
        image_data (bytes): The image data as bytes.
        filename (str): The filename provided by the user.

    Returns:
        str: The filepath where the image was saved, or None if an error occurred.
    """

    # Validate filename
    if not filename:
        print("Error: Filename cannot be empty.")
        return None

    # Secure the filename using werkzeug.utils.secure_filename
    filename = secure_filename(filename)

    if not filename:
        print("Error: Invalid filename after sanitization.")
        return None

    # Check for directory separators
    if '/' in filename or '\\' in filename:
        print("Error: Filename cannot contain directory separators.")
        return None

    # Check for ".." sequences
    if ".." in filename:
        print("Error: Filename cannot contain '..' sequences.")
        return None

    # Check for single path components
    if filename == "." or filename == "..":
        print("Error: Filename cannot be a single path component ('.' or '..').")
        return None

    # Check allowed extensions
    if not allowed_file(filename):
        print("Error: Invalid file extension.")
        return None

    # Create the upload folder if it doesn't exist
    if not os.path.exists(UPLOAD_FOLDER):
        try:
            os.makedirs(UPLOAD_FOLDER)
        except OSError as e:
            print(f"Error creating upload directory: {e}")
            return None

    # Construct the full filepath
    filepath = os.path.join(UPLOAD_FOLDER, filename)

    try:
        # Encode the image data using base64
        encoded_image = base64.b64encode(image_data)

        # Write the encoded image to the file
        with open(filepath, 'wb') as f:  # Use 'wb' for binary write
            f.write(encoded_image)

        # Set file permissions (restrictive) - adjust as needed for your environment
        os.chmod(filepath, 0o600)  # Owner read/write only

        return filepath

    except Exception as e:
        print(f"Error writing image to file: {e}")
        return None

if __name__ == '__main__':
    # Example usage (replace with actual image data and filename)
    # Create a dummy image file for testing
    with open("test_image.jpg", "wb") as f:
        f.write(b"Dummy image data")

    with open("test_image.jpg", "rb") as image_file:
        image_data = image_file.read()

    filename = "my_image.png"  # Example filename

    filepath = upload_image(image_data, filename)

    if filepath:
        print(f"Image saved to: {filepath}")
    else:
        print("Image upload failed.")

    # Test with invalid filenames
    upload_image(image_data, "../../../evil.txt") # Path traversal attempt
    upload_image(image_data, "evil/evil.txt") # Directory traversal attempt
    upload_image(image_data, "evil.php") # Invalid extension
    upload_image(image_data, ".") # Single path component
    upload_image(image_data, "") # Empty filename

