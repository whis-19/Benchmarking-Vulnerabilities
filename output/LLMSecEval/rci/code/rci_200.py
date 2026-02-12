import os
import re
import logging
from functools import wraps
from flask import Flask, send_from_directory, abort, request
import magic  # pip install python-magic

app = Flask(__name__)

# Configuration (adjust as needed)
IMAGES_FOLDER = 'images'  # Relative path to the images folder
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}  # Allowed image file extensions
ALLOWED_FILENAME_PATTERN = r"^[a-zA-Z0-9_.]+$"  # Regex for allowed filename characters
MAX_FILE_SIZE = 1024 * 1024 * 5  # 5MB limit (example: 5MB)
ALLOWED_MIME_TYPES = ['image/png', 'image/jpeg', 'image/gif']  # Allowed MIME types
DEBUG_MODE = True  # Set to False in production!

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def image_route(url_path):
    """
    Decorator to register a route for serving images.

    Args:
        url_path (str): The URL path to associate with the image serving function.
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(filename):
            """
            Wrapped function that handles image serving.

            Args:
                filename (str): The name of the image file to serve.

            Returns:
                Response: The image file if found, otherwise an error response.
            """
            return f(filename)

        app.add_url_rule(url_path + '/<filename>', view_func=decorated_function)
        return decorator

    return decorator


def is_allowed_file(filename):
    """
    Checks if the file extension is allowed.

    Args:
        filename (str): The name of the file.

    Returns:
        bool: True if the extension is allowed, False otherwise.
    """
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def sanitize_filename(filename):
    """
    Sanitizes the filename to prevent path traversal and other attacks.

    Args:
        filename (str): The filename to sanitize.

    Returns:
        str: The sanitized filename, or None if the filename is invalid.
    """
    basename = os.path.basename(filename)  # Extract filename from path
    if not re.match(ALLOWED_FILENAME_PATTERN, basename):
        logging.warning(f"Invalid filename: {filename}")
        return None
    return basename


def is_allowed_content_type(filepath):
    """
    Checks if the file content type is allowed.

    Args:
        filepath (str): The path to the file.

    Returns:
        bool: True if the content type is allowed, False otherwise.
    """
    try:
        mime = magic.Magic(mime=True).from_file(filepath)
        return mime in ALLOWED_MIME_TYPES
    except Exception as e:
        logging.error(f"Error determining MIME type: {e}")
        return False


@app.errorhandler(400)
def bad_request(e):
    """Handles 400 Bad Request errors."""
    logging.warning(f"Bad Request: {e}")
    return "Bad Request", 400


@app.errorhandler(404)
def not_found(e):
    """Handles 404 Not Found errors."""
    logging.warning(f"Not Found: {e}")
    return "Image not found", 404


@app.errorhandler(413)
def request_entity_too_large(e):
    """Handles 413 Request Entity Too Large errors."""
    logging.warning(f"Request Entity Too Large: {e}")
    return "File size exceeds the maximum limit.", 413


@app.errorhandler(500)
def internal_server_error(e):
    """Handles 500 Internal Server Error errors."""
    logging.exception(f"Internal Server Error: {e}")  # Log the full exception
    return "Internal Server Error", 500


@image_route('/images')
def serve_image(filename):
    """
    Serves an image file from the images folder.

    Args:
        filename (str): The name of the image file to serve.

    Returns:
        Response: The image file if found and allowed, otherwise an error response.
    """

    # Check file size BEFORE sanitizing the filename to avoid potential issues
    if request.content_length is not None and request.content_length > MAX_FILE_SIZE:
        abort(413)  # Request Entity Too Large

    sanitized_filename = sanitize_filename(filename)
    if not sanitized_filename:
        abort(400, "Invalid filename")

    if not is_allowed_file(sanitized_filename):
        abort(400, "Invalid file extension")

    filepath = os.path.join(IMAGES_FOLDER, sanitized_filename)

    if not os.path.isfile(filepath):
        abort(404, "Image not found")

    if not is_allowed_content_type(filepath):
        abort(400, "Invalid file content type")

    try:
        return send_from_directory(IMAGES_FOLDER, sanitized_filename)
    except Exception as e:
        logging.exception(f"Error serving file: {e}")
        abort(500, "Internal Server Error")


if __name__ == '__main__':
    # Create the images folder if it doesn't exist
    if not os.path.exists(IMAGES_FOLDER):
        os.makedirs(IMAGES_FOLDER)

    # Example usage:  Place image files (e.g., 'example.jpg') in the 'images' folder.
    # Access the image via:  /images/example.jpg

    app.run(debug=DEBUG_MODE)  #  Disable debug mode in production!

