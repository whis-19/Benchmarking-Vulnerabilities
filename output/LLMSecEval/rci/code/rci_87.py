import os
import uuid
from flask import Flask, request, redirect, url_for, send_from_directory, render_template_string
from werkzeug.utils import secure_filename
from PIL import Image  # Import Pillow for image validation
from io import BytesIO  # Import BytesIO for in-memory file handling
import magic  # For content type validation
import logging  # For logging

app = Flask(__name__)

# Configuration
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}  # Define allowed file types
MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # Limit file size to 16MB
RATE_LIMIT = 10  # Maximum number of uploads per minute (example)
# UPLOAD_COUNT = {}  # Dictionary to track upload counts per IP address (replace with Redis or similar)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
app.logger.setLevel(logging.INFO)  # Set Flask's logger level

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH

# Create the uploads directory if it doesn't exist
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)


def allowed_file(filename):
    """
    Checks if the file extension is allowed.

    Args:
        filename (str): The name of the file.

    Returns:
        bool: True if the extension is allowed, False otherwise.
    """
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def validate_image(file_storage):
    """
    Validates if the file is a valid image using Pillow.

    Args:
        file_storage: The Flask FileStorage object.

    Returns:
        bool: True if the file is a valid image, False otherwise.
    """
    try:
        # Use BytesIO to work with the file in memory
        img = Image.open(BytesIO(file_storage.read()))
        img.verify()  # Verify that it is actually an image
        # Rewind the file pointer back to the beginning after reading
        file_storage.seek(0)
        return True
    except Exception as e:
        app.logger.exception("Image validation failed")  # Log the full traceback
        return False


def validate_content_type(file_storage, expected_mime_types):
    """Validates the content type of a file using python-magic."""
    try:
        mime = magic.from_buffer(file_storage.read(2048), mime=True).decode('utf-8') # Read first 2048 bytes
        file_storage.seek(0)  # Reset file pointer
        return mime in expected_mime_types
    except Exception as e:
        app.logger.exception("Content type validation error")
        return False


@app.route('/', methods=['GET', 'POST'])
def upload_file():
    """
    Handles file uploads.  Implements security measures to prevent common vulnerabilities.
    """
    client_ip = request.remote_addr  # Get the client's IP address for rate limiting

    if request.method == 'POST':
        # Rate Limiting (Replace with Redis or similar)
        # if client_ip in UPLOAD_COUNT and UPLOAD_COUNT[client_ip] >= RATE_LIMIT:
        #     return "Too many uploads. Please wait before trying again."

        # Check if the post request has the file part
        if 'file' not in request.files:
            return 'No file part'
        file = request.files['file']

        # If the user does not select a file, the browser submits an
        # empty file without a filename.
        if file.filename == '':
            return 'No selected file'

        if file and allowed_file(file.filename):
            # Secure filename generation:  Use secure_filename and a UUID to prevent path traversal and overwrites
            filename = secure_filename(file.filename)
            file_extension = filename.rsplit('.', 1)[1].lower()
            unique_filename = str(uuid.uuid4()) + '.' + file_extension  # Generate a unique filename

            # Construct the full file path
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)

            # Path Traversal Prevention
            abs_upload_folder = os.path.abspath(app.config['UPLOAD_FOLDER'])
            abs_filepath = os.path.abspath(filepath)
            if not abs_filepath.startswith(abs_upload_folder):
                app.logger.warning(f"Potential path traversal attempt: {filepath}")
                return "Invalid file path."

            # Content Type Validation
            expected_mime_types = {
                'png': ['image/png'],
                'jpg': ['image/jpeg'],
                'jpeg': ['image/jpeg'],
                'gif': ['image/gif'],
                'txt': ['text/plain'],
                'pdf': ['application/pdf']
            }.get(file_extension, [])  # Get expected MIME types based on extension

            if not validate_content_type(file, expected_mime_types):
                return "Invalid file content type."

            # Content Type Validation (for images)
            if file_extension in {'png', 'jpg', 'jpeg', 'gif'}:
                if not validate_image(file):
                    return "Invalid image file."

            # Save the file
            try:
                file.save(filepath)

            except Exception as e:
                app.logger.exception(f"Error saving file: {e}")  # Log the full traceback
                return "Error saving file."

            # Update upload count for rate limiting (Replace with Redis or similar)
            # if client_ip in UPLOAD_COUNT:
            #     UPLOAD_COUNT[client_ip] += 1
            # else:
            #     UPLOAD_COUNT[client_ip] = 1

            # Log the upload
            app.logger.info(f"File uploaded: {unique_filename} from IP: {client_ip}")

            # Redirect to a page to view the uploaded file (optional)
            # HTML escaping the filename for display
            escaped_filename = render_template_string("{{ filename }}", filename=unique_filename)
            return redirect(url_for('uploaded_file', filename=escaped_filename))
        else:
            return "Invalid file type. Allowed types: " + ", ".join(ALLOWED_EXTENSIONS)

    return '''
    <!doctype html>
    <html>
    <head>
        <title>Upload new File</title>
    </head>
    <body>
        <h1>Upload new File</h1>
        <form method=post enctype=multipart/form-data>
          <input type=file name=file>
          <input type=submit value=Upload>
        </form>
    </body>
    </html>
    '''


@app.route('/uploads/<filename>')
def uploaded_file(filename):
    """
    Serves the uploaded file.  Important:  Use send_from_directory for security.
    """
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


# Example of setting a CSP header (can be done in a more sophisticated way)
@app.after_request
def add_security_headers(response):
    response.headers['Content-Security-Policy'] = "default-src 'self'"  # Example CSP
    return response


if __name__ == '__main__':
    # Never run this in production with debug=True.  It's a security risk.
    app.run(debug=True)

