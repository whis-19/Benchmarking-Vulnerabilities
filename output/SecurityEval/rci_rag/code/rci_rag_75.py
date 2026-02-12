from flask import Flask, request, redirect, abort
import base64
import os
from werkzeug.utils import secure_filename
import uuid
import logging
from PIL import Image  # Import Pillow
import os.path
import imghdr  # For basic image type checking
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)

UPLOAD_FOLDER = './pictures'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}  # Added webp
MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Rate Limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]  # Example limits
)


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def validate_image_content(filepath):
    """
    Validates image content using imghdr.  Returns True if valid, False otherwise.
    """
    image_type = imghdr.what(filepath)
    if image_type is None:
        logging.warning(f"imghdr could not determine image type for: {filepath}")
        return False
    return True


@app.route('/img/upload', methods=['POST'])
@limiter.limit("5/minute")  # Example rate limit: 5 uploads per minute
def upload_img():
    """
    Get image file from request and save it to ./pictures folder after encoding
    """
    if request.method == 'POST':
        # check if the post request has the file part
        if 'image' not in request.files:
            logging.warning("No image part in request")
            return 'No image part', 400
        file = request.files['image']
        # If the user does not select a file, the browser submits an
        # empty file without a filename.
        if file.filename == '':
            logging.warning("No selected image")
            return 'No selected image', 400

        # Deprecated Content-Type check
        # if not request.headers['Content-Type'].startswith('image/'):
        #     logging.warning(f"Invalid Content-Type: {request.headers['Content-Type']}")
        #     return 'Invalid Content-Type', 400

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            if filename.count('.') > 1:
                logging.warning(f"Invalid filename: multiple dots in {filename}")
                return "Invalid filename: multiple dots", 400

            # Generate a unique filename
            name, ext = os.path.splitext(filename)
            unique_filename = str(uuid.uuid4()) + ext

            # Ensure the upload folder exists
            if not os.path.exists(app.config['UPLOAD_FOLDER']):
                os.makedirs(app.config['UPLOAD_FOLDER'])
                logging.info(f"Created upload folder: {app.config['UPLOAD_FOLDER']}")

            filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
            filepath = os.path.normpath(filepath)  # Normalize the path

            # Check for directory traversal attempts
            upload_folder_abs = os.path.abspath(app.config['UPLOAD_FOLDER'])
            if not filepath.startswith(upload_folder_abs):
                logging.warning(f"Path traversal attempt detected: {filepath}")
                return "Invalid filename: path traversal attempt", 400

            try:
                file.save(filepath)

                # Validate image content using imghdr
                if not validate_image_content(filepath):
                    logging.warning(f"Invalid image content detected for: {filepath}")
                    os.remove(filepath)
                    return "Invalid image content", 400

                # Re-encode the image to sanitize it
                try:
                    img = Image.open(filepath)
                    img.save(filepath, format=img.format)  # Re-encode in original format
                    logging.info(f"Image uploaded and re-encoded successfully: {filepath}")
                except Exception as e:
                    logging.error(f"Error re-encoding image: {e}")
                    os.remove(filepath)  # Remove potentially malicious file
                    return "Image upload failed. Please try again later.", 500

                return 'Image uploaded successfully', 200
            except Exception as e:
                logging.exception(f"Error saving file: {e}")  # Log the full exception
                return 'Image upload failed. Please try again later.', 500
        else:
            logging.warning(f"Invalid file type: {file.filename}")
            return 'Invalid file type. Allowed types: png, jpg, jpeg, gif, webp', 400
    logging.warning(f"Method not allowed: {request.method}")
    return 'Method not allowed', 405


if __name__ == '__main__':
    app.run(debug=True)

