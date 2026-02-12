import os
import uuid
from flask import request, Flask, abort
from werkzeug.utils import secure_filename
import mimetypes  # For MIME type checking
import logging
import magic  # For more reliable MIME type detection (requires libmagic)

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}
UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB limit

# Ensure the upload folder exists
if not os.path.exists(UPLOAD_FOLDER):
    try:
        os.makedirs(UPLOAD_FOLDER)
        logging.info(f"Created upload folder: {UPLOAD_FOLDER}")
    except OSError as e:
        logging.error(f"Failed to create upload folder: {e}")
        raise  # Re-raise the exception to prevent the app from running without the folder


def allowed_file(filename):
    """
    Check if the file extension is allowed (case-insensitive).
    """
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/upload', methods=['POST'])
def upload():
    """Handles file uploads, ensuring security and proper validation."""
    username = request.form.get('username')
    file = request.files.get('file')

    if not username:
        logging.warning("Upload failed: Username is missing.")
        return "Error: Username is required.", 400

    if not file:
        logging.warning("Upload failed: File is missing.")
        return "Error: File is required.", 400

    if file.filename == '':
        logging.warning("Upload failed: No file selected.")
        return "Error: No file selected.", 400

    # Check file size BEFORE doing anything else
    file.seek(0, os.SEEK_END)  # Go to the end of the file
    file_length = file.tell()  # Get the file size
    file.seek(0, 0)  # Rewind to the beginning of the file

    if file_length > MAX_FILE_SIZE:
        logging.warning(f"Upload blocked: File size exceeds limit ({MAX_FILE_SIZE} bytes).")
        return "Error: File size exceeds the limit.", 413  # Request Entity Too Large

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)

        # Generate a unique filename to prevent collisions and potential issues.
        unique_filename = str(uuid.uuid4()) + os.path.splitext(filename)[1]  # Keep extension
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)

        # Sanitize the username (example - allow only alphanumeric and underscore)
        sanitized_username = ''.join(c for c in username if c.isalnum() or c == '_')

        # Check MIME type using libmagic for more reliable detection
        try:
            mime = magic.Magic(mime=True)
            mime_type = mime.from_file(filepath)
        except Exception as e:
            logging.error(f"Error during MIME type detection: {e}")
            mime_type = None  # Handle the case where MIME type detection fails

        allowed_mime_types = ['image/jpeg', 'image/png', 'image/gif', 'application/pdf', 'text/plain']
        if mime_type not in allowed_mime_types and mime_type is not None:  # Handle None case
            logging.warning(f"Upload blocked: Invalid MIME type: {mime_type}")
            try:
                os.remove(filepath)  # Remove the file if MIME type is invalid
            except OSError as e:
                logging.error(f"Failed to remove file after MIME type check: {e}")
            return "Error: Invalid file type (MIME type mismatch).", 400

        try:
            file.save(filepath)
            logging.info(f"File uploaded successfully: {filepath} by user {sanitized_username}")
            return f"File uploaded successfully to {filepath}", 200
        except Exception as e:
            logging.error(f"File save failed: {e}")
            return "Error: File save failed.", 500  # Internal Server Error

    else:
        logging.warning(f"Upload blocked: Invalid file type. Filename: {file.filename}")
        return "Error: Invalid file type. Allowed types: " + ", ".join(ALLOWED_EXTENSIONS), 400


@app.errorhandler(500)
def internal_server_error(e):
    """Handles internal server errors and logs the error."""
    logging.exception("Internal Server Error")
    return "Internal Server Error", 500


if __name__ == '__main__':
    #  DO NOT USE DEBUG MODE IN PRODUCTION
    #  Consider using a WSGI server like gunicorn or uWSGI for production deployment
    app.run(debug=False)

