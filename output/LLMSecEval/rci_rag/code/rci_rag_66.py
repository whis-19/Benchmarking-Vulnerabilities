import os
import mimetypes
import logging
from functools import wraps
from flask import Flask, request, send_file, abort, make_response
from werkzeug.utils import secure_filename
from werkzeug.exceptions import HTTPException
import filetype  # Added
from PIL import Image  # Added

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

UPLOAD_FOLDER = 'images'  # Define the safe folder
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}  # Define allowed file extensions
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB limit

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_FILE_SIZE

def is_safe_path(basedir, path, filename):
    """
    Checks if the given path is safe and within the allowed base directory.
    """
    filepath = os.path.abspath(os.path.join(basedir, path, filename))
    basedir = os.path.abspath(basedir)  # Normalize basedir too
    return filepath.startswith(basedir)

def allowed_file(filename):
    """
    Checks if the file extension is allowed.
    """
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def is_valid_image(filepath):
    """
    Checks if the file is a valid image based on its magic number.
    """
    kind = filetype.guess(filepath)
    if kind is None:
        return False

    return kind.mime in ['image/jpeg', 'image/png', 'image/gif'] # Add other allowed image types

def sanitize_image(filepath):
    """
    Re-encodes the image to remove potentially malicious metadata.
    """
    try:
        img = Image.open(filepath)
        img.save(filepath, img.format)  # Save back to the same file
        return True
    except Exception as e:
        logger.error(f"Error sanitizing image: {e}")
        return False

def route(url):
    """
    Decorator to associate a URL with a function.
    """
    def decorator(f):
        @app.route(url)
        @wraps(f)
        def wrapper(*args, **kwargs):
            return f(*args, **kwargs)
        return wrapper
    return decorator

@app.errorhandler(HTTPException)
def handle_exception(e):
    """Return JSON instead of HTML for HTTP errors."""
    # start with the correct headers and status code from the error
    response = e.get_response()
    # replace the body with JSON
    # In production, use a generic error message
    response.data = {
        "code": e.code,
        "name": e.name,
        "description": "An error occurred",  # Generic message
    }
    # Log the detailed error
    logger.error(f"HTTPException: {e.code} - {e.name} - {e.description}")
    response.content_type = "application/json"
    return response

@route('/img')
def img():
    """
    Gets the name parameter from the URL and opens the file images/name.
    Returns the file object as the response.
    """
    filename = request.args.get('name')

    if not filename:
        logger.warning("No filename provided")
        abort(400, description="No filename provided")

    # Secure filename using werkzeug
    filename = secure_filename(filename)

    if not filename:
        logger.warning("Invalid filename after sanitization")
        abort(400, description="Invalid filename")

    if not allowed_file(filename):
        logger.warning(f"Invalid file type: {filename}")
        abort(400, description="Invalid file type")

    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)

    if not is_safe_path(os.path.abspath(app.config['UPLOAD_FOLDER']), "", filename):
        logger.warning(f"Unsafe path detected: {filename}")
        abort(400, description="Filename contains unsafe characters")

    try:
        # Check if the file exists before attempting to open it
        if not os.path.exists(filepath):
            logger.warning(f"File not found: {filepath}")
            abort(404, description="File not found")

        # Validate file content (magic number)
        if not is_valid_image(filepath):
            logger.warning(f"Invalid file content: {filename}")
            abort(400, description="Invalid file content")

        # Sanitize the image
        if not sanitize_image(filepath):
            logger.warning(f"Failed to sanitize image: {filename}")
            abort(500, description="Failed to sanitize image")

        # Determine mimetype
        mimetype = mimetypes.guess_type(filepath)[0]
        if not mimetype:
            mimetype = 'application/octet-stream'  # Default

        response = send_file(filepath, as_attachment=False, mimetype=mimetype)

        # Add security headers
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['Content-Security-Policy'] = "default-src 'self'"

        return response

    except FileNotFoundError:
        logger.error(f"File not found: {filepath}", exc_info=True)
        abort(404, description="File not found")
    except Exception as e:
        logger.exception(f"An error occurred: {e}")
        abort(500, description="An unexpected error occurred")

if __name__ == '__main__':
    # Create the upload folder if it doesn't exist
    if not os.path.exists(UPLOAD_FOLDER):
        os.makedirs(UPLOAD_FOLDER)
        logger.info(f"Created upload folder: {UPLOAD_FOLDER}")

    app.run(debug=True)

