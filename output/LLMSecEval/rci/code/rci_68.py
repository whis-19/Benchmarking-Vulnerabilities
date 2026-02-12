import os
import mimetypes
import logging
from flask import Flask, request, send_file, abort, make_response
from werkzeug.utils import secure_filename
from python_magic import Magic  # Import python-magic
from PIL import Image
from io import BytesIO
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address


app = Flask(__name__)

# Define a safe directory for storing images.  Crucially, this should be
# outside of the web server's document root to prevent direct access.
UPLOAD_FOLDER = '/path/to/your/safe/image/directory'  # Replace with a real path
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Ensure the upload folder exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Check if UPLOAD_FOLDER is outside the document root
if os.path.abspath(UPLOAD_FOLDER).startswith(os.path.abspath('.')):
    logging.error("UPLOAD_FOLDER is inside the document root! This is a security risk.")
    raise ValueError("UPLOAD_FOLDER must be outside the document root")

# Initialize Flask-Limiter for rate limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day, 50 per hour"]  # Example rate limits
)


def is_valid_image(filepath):
    """
    Verifies if a file is a valid image using Pillow.
    """
    try:
        img = Image.open(filepath)
        img.verify()  # Verify that it's an image
        img.close()
        return True
    except (IOError, SyntaxError) as e:
        logging.warning(f"Invalid image file: {filepath} - {e}")
        return False


@app.route('/img')
@limiter.limit("10/minute")  # Apply rate limiting to the image serving endpoint
def img():
    """
    Serves an image file securely.  Prevents path traversal vulnerabilities.
    """
    filename = request.args.get('file')

    if not filename:
        logging.warning("Missing 'file' parameter in request.")
        return "Missing 'file' parameter", 400

    # Sanitize the filename to prevent path traversal attacks.
    filename = secure_filename(filename)

    if not filename:
        logging.warning("Invalid filename provided.")
        return "Invalid filename", 400  # Or a more informative error

    # Limit filename length
    if len(filename) > 255:  # Or a reasonable limit
        logging.warning(f"Filename too long: {filename}")
        return "Filename too long", 400

    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)

    # Check if the file exists.  This is important to prevent errors
    # and potential information disclosure.
    if not os.path.exists(filepath):
        logging.warning(f"File not found: {filepath}")
        abort(404)  # File not found

    # Resolve symlinks and check if the resolved path is actually within the allowed directory.
    real_filepath = os.path.realpath(filepath)
    real_upload_folder = os.path.realpath(app.config['UPLOAD_FOLDER'])

    if not real_filepath.startswith(real_upload_folder):
        logging.warning(f"Attempted path traversal: {filepath}")
        abort(403)  # Forbidden - Attempted path traversal

    try:
        # Determine the MIME type using python-magic
        try:
            mime = Magic(mime=True)
            mimetype = mime.from_file(filepath)
        except Exception as e:
            logging.error(f"Error determining MIME type for {filepath}: {e}")
            logging.warning("Falling back to mimetypes.guess_type")
            mimetype = mimetypes.guess_type(filepath)[0]  # Fallback to extension-based
            if not mimetype:
                logging.warning("Could not determine MIME type. Using application/octet-stream")
                mimetype = 'application/octet-stream'  # Default MIME type
            else:
                logging.warning(f"Using fallback MIME type: {mimetype} for {filepath}") # Log fallback usage


        # Validate image content using Pillow
        if mimetype.startswith('image/'):
            if not is_valid_image(filepath):
                logging.warning(f"Invalid image content: {filepath}")
                abort(400)  # Or a more specific error

        # Use send_file for secure file serving.  It handles proper headers
        # and streaming.
        response = make_response(send_file(filepath, mimetype=mimetype))
        response.headers['Content-Security-Policy'] = "default-src 'self'"  # Example CSP
        return response

    except FileNotFoundError:
        logging.warning(f"File not found (again): {filepath}")
        abort(404)  # File not found (again, in case it disappeared)
    except OSError as e:
        logging.error(f"OS Error serving file {filepath}: {e}")
        abort(500)
    except Exception as e:
        logging.exception(f"Unexpected error serving file {filepath}: {e}")
        abort(500)  # Internal Server Error


if __name__ == '__main__':
    app.run(debug=True)  # Disable debug mode in production!

