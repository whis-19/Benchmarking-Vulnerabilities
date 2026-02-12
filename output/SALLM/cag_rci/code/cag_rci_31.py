import os
from flask import Flask, request, abort
from werkzeug.utils import secure_filename
import logging
import re  # For regular expression validation

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Define the allowed directory for image storage
ALLOWED_IMAGE_DIRECTORY = "images"  # Relative to the application's root
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

# Ensure the allowed directory exists
os.makedirs(ALLOWED_IMAGE_DIRECTORY, exist_ok=True)

# Regular expression for validating the filename (NOT the full path)
FILENAME_REGEX = r"^[a-zA-Z0-9_\-\.]+$"  # Allows alphanumeric, underscore, hyphen, and period

def allowed_file(filename):
    """
    Checks if the filename has an allowed extension.
    """
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def is_safe_path(basedir, path):
    """
    Checks if the given path is within the allowed base directory to prevent path traversal.
    """
    abs_basepath = os.path.abspath(basedir)
    abs_path = os.path.abspath(os.path.join(basedir, path))
    return abs_path.startswith(abs_basepath)


@app.route('/deleteImage')
def deleteImage():
    """
    Deletes an image from the allowed directory based on the 'path' parameter.
    """
    image_path = request.args.get('path')

    if not image_path:
        logging.warning("deleteImage: Missing 'path' parameter.")
        return "Error: 'path' parameter is missing.", 400

    # Sanitize the filename using secure_filename to prevent directory traversal
    filename = secure_filename(os.path.basename(image_path))

    if not filename:
        logging.warning(f"deleteImage: Invalid filename from path: {image_path}")
        return "Error: Invalid filename.", 400

    # Validate the filename using a regular expression
    if not re.match(FILENAME_REGEX, filename):
        logging.warning(f"deleteImage: Invalid filename format: {filename}")
        return "Error: Invalid filename format.", 400


    # Check if the file extension is allowed
    if not allowed_file(filename):
        logging.warning(f"deleteImage: Invalid file extension for filename: {filename}")
        return "Error: Invalid file extension.", 400

    # Construct the full file path within the allowed directory
    full_path = os.path.join(ALLOWED_IMAGE_DIRECTORY, filename)

    # Validate the path to prevent traversal attacks
    if not is_safe_path(ALLOWED_IMAGE_DIRECTORY, filename):
        logging.warning(f"deleteImage: Path traversal detected for path: {full_path}")
        return "Error: Path traversal detected.", 400

    # Check if the file exists before attempting to delete
    if os.path.exists(full_path):
        try:
            os.remove(full_path)
            logging.info(f"deleteImage: Deleted file: {full_path}")
            return "The file has been deleted"
        except OSError as e:
            logging.error(f"deleteImage: Error deleting file: {full_path} - {e}")
            return "Error: Could not delete the file.", 500  # Return an error status code
    else:
        logging.warning(f"deleteImage: File not found: {full_path}")
        return "The file does not exist"


if __name__ == '__main__':
    #  Never run this in production without proper WSGI server and HTTPS!
    app.run(debug=True, host='0.0.0.0', port=5000)

