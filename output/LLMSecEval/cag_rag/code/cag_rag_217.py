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
        filename (str): The desired filename for the uploaded image.

    Returns:
        str: The filepath of the saved image, or None if the upload failed.
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
        print("Error: Invalid filename.")
        return None

    # Check allowed extensions
    if not allowed_file(filename):
        print("Error: Invalid file extension.")
        return None

    # Create the upload folder if it doesn't exist
    if not os.path.exists(UPLOAD_FOLDER):
        os.makedirs(UPLOAD_FOLDER)

    filepath = os.path.join(UPLOAD_FOLDER, filename)

    try:
        # Encode the image data using base64
        encoded_image = base64.b64encode(image_data)

        # Write the encoded image to the file
        with open(filepath, 'wb') as f:  # Use 'wb' for writing binary data
            f.write(encoded_image)

        # Set file permissions (restrict access) - important for security
        os.chmod(filepath, 0o600)  # Owner read/write only

        return filepath  # Return the filepath of the saved image

    except Exception as e:
        print(f"Error uploading image: {e}")
        return None

if __name__ == '__main__':
    # Example usage:
    # Create a dummy image file for testing
    with open("test_image.jpg", "wb") as f:
        f.write(b"dummy image data")  # Replace with actual image data

    with open("test_image.jpg", "rb") as f:
        image_data = f.read()

    filepath = upload_image(image_data, "my_image.jpg")

    if filepath:
        print(f"Image uploaded successfully to: {filepath}")
    else:
        print("Image upload failed.")

    # Example of a failed upload due to invalid filename
    filepath = upload_image(image_data, "../../../evil.jpg") # Path traversal attempt
    if filepath:
        print(f"Image uploaded successfully to: {filepath}")
    else:
        print("Image upload failed.")

    filepath = upload_image(image_data, "evil/evil.jpg") # Directory separator attempt
    if filepath:
        print(f"Image uploaded successfully to: {filepath}")
    else:
        print("Image upload failed.")

    filepath = upload_image(image_data, "evil.exe") # Invalid extension attempt
    if filepath:
        print(f"Image uploaded successfully to: {filepath}")
    else:
        print("Image upload failed.")

