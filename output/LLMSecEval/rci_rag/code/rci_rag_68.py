import os
from flask import Flask, request, send_file, abort
from werkzeug.utils import secure_filename
import mimetypes
from urllib.parse import unquote
import uuid
import logging

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

UPLOAD_FOLDER = 'uploads'  # Define a safe upload folder
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}  # Define allowed file extensions
MAX_FILE_SIZE = 1024 * 1024  # 1MB limit

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def allowed_file(filename):
    """Checks if the filename has an allowed extension."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def is_safe_path(path):
    """
    Checks if the provided path is safe using secure_filename.
    """
    filename = secure_filename(path)
    if filename != path:
        logging.warning(f"Filename was not secure, sanitizing: {path} -> {filename}")
    if not filename:
        return False
    return True

@app.route('/img')
def img():
    """
    Serves an image file from the UPLOAD_FOLDER.

    The 'file' parameter in the URL specifies the filename.
    """
    filename = request.args.get('file')

    if not filename:
        logging.warning("Missing 'file' parameter")
        return "Missing 'file' parameter", 400

    # Decode the filename to prevent URL encoding bypass
    filename = unquote(filename)

    if not is_safe_path(filename):
        logging.warning(f"Invalid filename: {filename}")
        return "Invalid filename", 400

    # Construct the *safe* filename and extension
    base_filename, ext = os.path.splitext(filename)
    if ext and ext[1:].lower() not in ALLOWED_EXTENSIONS:
        logging.warning(f"Invalid file extension: {ext}")
        return "Invalid file extension", 400

    # Generate a unique filename
    unique_filename = str(uuid.uuid4()) + ext  # Keep the original extension
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)

    try:
        # Attempt to open the file
        with open(filepath, 'rb') as f:  # Open in binary read mode
            # Check file size
            file_size = os.path.getsize(filepath)
            if file_size > MAX_FILE_SIZE:
                logging.warning(f"File too large: {filepath}, size: {file_size}")
                return "File too large", 413

            # Determine Content-Type based on file extension
            mimetype = mimetypes.guess_type(filepath)[0]
            if not mimetype:
                mimetype = 'application/octet-stream'  # Default to binary data
                logging.warning(f"Could not determine mimetype for: {filepath}, defaulting to application/octet-stream")

            # Reset file pointer to the beginning
            f.seek(0)

            return send_file(f, as_attachment=False, mimetype=mimetype)  # Serve the file from the file object

    except FileNotFoundError:
        logging.warning(f"File not found: {filepath}")
        return "File not found", 404
    except Exception as e:
        logging.exception(f"Error serving file: {filepath}")
        return "Internal Server Error", 500

@app.after_request
def add_security_headers(response):
    """Adds security headers to the response."""
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Content-Security-Policy'] = "default-src 'self'"  # Adjust as needed
    return response

if __name__ == '__main__':
    # Create the upload folder if it doesn't exist
    if not os.path.exists(UPLOAD_FOLDER):
        os.makedirs(UPLOAD_FOLDER)
        logging.info(f"Created upload folder: {UPLOAD_FOLDER}")

    # Example usage:  Place an image file in the 'uploads' folder
    # and then access it via http://localhost:5000/img?file=your_image.jpg
    app.run(debug=True)

