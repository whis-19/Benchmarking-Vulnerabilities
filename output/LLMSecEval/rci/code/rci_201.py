import os
import uuid
from flask import Flask, request, send_file, abort
from werkzeug.utils import secure_filename
import mimetypes
import logging
import magic  # Import the python-magic library

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Define a safe directory for storing images.  Crucially, this should be
# outside of the web server's document root.  For example:
UPLOAD_FOLDER = '/var/www/images'  # Change this to a secure location
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
MAX_FILENAME_LENGTH = 255  # Limit filename length
MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB limit
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH

# Ensure the upload folder exists
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)


@app.route('/img')
def img():
    """
    Serves an image file.  This function is designed to be secure by:

    1.  Using `secure_filename` to sanitize the filename provided by the user.
    2.  Checking that the requested file exists within a designated safe directory.
    3.  Using `send_file` to securely serve the file.
    """
    filename = request.args.get('file')

    if not filename:
        logging.warning("No filename provided")
        return "Error: No filename provided", 400

    # Sanitize the filename to prevent path traversal attacks.
    filename = secure_filename(filename)

    if len(filename) > MAX_FILENAME_LENGTH:
        logging.warning(f"Filename too long: {filename}")
        return "Error: Filename too long", 400

    # Construct the full path to the file.  Crucially, we join the safe
    # upload folder with the sanitized filename.
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)

    # Check if the file exists and is within the allowed directory.
    # This is the most important security check.  We use os.path.abspath to
    # get the absolute path of both the requested file and the upload folder,
    # and then check if the file's path starts with the upload folder's path.
    # This prevents attackers from using path traversal techniques (e.g., "file=../../etc/passwd")
    if not os.path.exists(filepath) or not os.path.abspath(filepath).startswith(os.path.abspath(app.config['UPLOAD_FOLDER'])):
        logging.warning(f"File not found or access denied: {filepath}")
        return "Error: File not found or access denied", 404

    try:
        # **CRITICAL: Resolve path and re-validate just before send_file to prevent race conditions**
        real_filepath = os.path.realpath(filepath)
        if not real_filepath.startswith(os.path.realpath(app.config['UPLOAD_FOLDER'])):
            logging.warning(f"Attempted path traversal: {filepath} -> {real_filepath}")
            return "Error: File not found or access denied", 404

        # Use send_file to securely serve the file.  This handles proper
        # content type detection and streaming.
        return send_file(real_filepath, as_attachment=False)  # as_attachment=False displays in browser
    except FileNotFoundError:
        logging.error(f"File not found: {filepath}", exc_info=True)
        return "Error: File not found", 404
    except Exception as e:
        logging.exception(f"Error serving file: {e} - Filename: {filename}")  # Log the error for debugging
        return "Error: Internal server error", 500


@app.route('/upload', methods=['POST'])
def upload_file():
    """Handles file uploads, including security checks."""
    if 'file' not in request.files:
        return "Error: No file part", 400

    file = request.files['file']

    if file.filename == '':
        return "Error: No selected file", 400

    filename = secure_filename(file.filename)
    if len(filename) > MAX_FILENAME_LENGTH:
        return "Error: Filename too long", 400

    # Generate a unique filename to prevent overwrites
    unique_filename = str(uuid.uuid4()) + "_" + filename
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)

    try:
        # Save the file temporarily to determine its MIME type
        file.save(filepath)

        # Check content type using magic number
        mime = magic.Magic(mime=True)
        mime_type = mime.from_file(filepath)

        if mime_type not in ['image/jpeg', 'image/png', 'image/gif']:
            logging.warning(f"Invalid content type: {mime_type} for file {filename}")
            os.remove(filepath)  # Remove the file if it's invalid
            return "Error: Invalid file type", 400

        logging.info(f"File uploaded successfully: {filepath}")
        return "File uploaded successfully", 200
    except Exception as e:
        # Clean up the file if an error occurred during processing
        if os.path.exists(filepath):
            os.remove(filepath)
        logging.exception(f"Error saving file: {e} - Filename: {filename}")
        return "Error: Internal server error", 500


if __name__ == '__main__':
    #  Never run this in production.  Use a proper WSGI server like Gunicorn or uWSGI.
    app.run(debug=True, host='0.0.0.0')

