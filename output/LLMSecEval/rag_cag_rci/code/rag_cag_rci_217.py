from PIL import Image
from PIL import UnidentifiedImageError

def validate_image_content(file):
    """Validates the image content using Pillow."""
    try:
        img = Image.open(file)
        img.verify()  # Verify that it's an image
        img.close()
        file.seek(0)  # Reset file pointer
        return True
    except (IOError, SyntaxError, UnidentifiedImageError) as e:
        print(f"Invalid image: {e}")
        return False
    except Exception as e:
        print(f"Error validating image content: {e}")
        return False

# ... (Inside the upload_file function) ...
if file and allowed_file(file.filename):
    if not validate_file_content(file):
        abort(400, "Invalid file content (MIME type)")

    if file.filename.lower().endswith(('.png', '.jpg', '.jpeg', '.gif')):
        if not validate_image_content(file):
            abort(400, "Invalid image content (corrupted or malicious)")

