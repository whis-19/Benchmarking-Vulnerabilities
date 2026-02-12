import os
import uuid
import re
from flask import Flask, request, redirect, url_for, send_from_directory, make_response
from werkzeug.utils import secure_filename
import logging
import PyPDF2  # Import PyPDF2
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

UPLOAD_FOLDER = '/path/to/your/secure/uploads'  # Store outside web document root
ALLOWED_EXTENSIONS = {'pdf'}
MAX_FILE_SIZE = 16 * 1024 * 1024  # 16MB

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_FILE_SIZE  # File size limit

# Rate Limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],  # Example limits
    storage_uri="memory://"  # Use a persistent storage for production - consider Redis or similar for production
)

# Ensure the upload folder exists
if not os.path.exists(UPLOAD_FOLDER):
    try:
        os.makedirs(UPLOAD_FOLDER)
        # Restrict permissions on the upload folder
        os.chmod(UPLOAD_FOLDER, 0o700)  # Owner read/write/execute only
        logging.info(f"Created upload folder: {UPLOAD_FOLDER} with restricted permissions.")
    except OSError as e:
        logging.error(f"Failed to create upload folder: {e}")
        # Handle the error appropriately, e.g., exit the application
        raise

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def sanitize_filename(filename):
    """
    Further sanitizes the filename using a regular expression.
    """
    name, ext = os.path.splitext(filename)
    name = re.sub(r'[^a-zA-Z0-9_.-]', '', name)  # Allow alphanumeric, underscore, period, and hyphen
    return secure_filename(name + ext)

def validate_pdf_content(filepath):
    """Validates the content of the PDF file using PyPDF2."""
    try:
        with open(filepath, 'rb') as f:
            pdf = PyPDF2.PdfReader(f)
            # Attempt to access some content to verify it's a valid PDF
            num_pages = len(pdf.pages)
            if num_pages > 0:
                return True
            else:
                logging.warning("PDF has no pages.")
                return False
    except PyPDF2.errors.PdfReadError as e:
        logging.warning(f"Invalid PDF content: {e}")
        return False
    except Exception as e:
        logging.error(f"Error validating PDF content: {e}")
        return False

@app.route('/', methods=['GET', 'POST'])
@limiter.limit("5/minute")  # Limit uploads to 5 per minute
def upload_file():
    if request.method == 'POST':
        # check if the post request has the file part
        if 'file' not in request.files:
            logging.warning('No file part')
            return 'No file part', 400
        file = request.files['file']
        # If the user does not select a file, the browser submits an
        # empty file without a filename.
        if file.filename == '':
            logging.warning('No selected file')
            return 'No selected file', 400

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)  # Sanitize filename
            filename = sanitize_filename(filename) # Further sanitize

            # Additional validation:  Check for directory traversal attempts
            if filename.startswith('.') or '..' in filename or '/' in filename or '\\' in filename:
                logging.warning(f"Invalid filename: {filename} - potential directory traversal attempt.")
                return "Invalid filename", 400

            # Generate a UUID for the filename
            new_filename = str(uuid.uuid4()) + os.path.splitext(filename)[1]

            filepath = os.path.join(app.config['UPLOAD_FOLDER'], new_filename)

            # Double check that the path is within the allowed directory
            if not os.path.abspath(filepath).startswith(os.path.abspath(app.config['UPLOAD_FOLDER'])):
                logging.warning(f"Attempted to save file outside of allowed directory: {filepath}")
                return "Invalid filename", 400

            try:
                file.save(filepath)
                logging.info(f"File saved successfully: {filepath}")

                # Validate PDF content
                if not validate_pdf_content(filepath):
                    os.remove(filepath)  # Remove the invalid file
                    logging.warning("Invalid PDF content detected. File removed.")
                    return "Invalid PDF content", 400

                # In a real application, you would store the original filename
                # and the UUID filename in a database.
                return 'File uploaded successfully'
            except (IOError, OSError) as e:  # Catch more specific exceptions
                logging.error(f"Error saving file: {e}")
                return 'Error uploading file', 500
        else:
            logging.warning(f"Invalid file type. Allowed types: {ALLOWED_EXTENSIONS}")
            return 'Invalid file type. Only PDF files are allowed.', 400

    resp = make_response('''
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
    ''')
    resp.headers['Content-Security-Policy'] = "default-src 'self'"  # Restrict to same origin
    return resp

@app.route('/uploads/<name>')
def download_file(name):
    # This route is intentionally disabled for security reasons.
    # Serving user-uploaded files directly from the web server is a security risk.
    # If you need to serve files, consider using a separate, dedicated service
    # with strict access controls and sanitization.
    #
    # If this route were enabled, it would be crucial to set the Content-Type header
    # explicitly based on the allowed file extension and also set
    # X-Content-Type-Options: nosniff to prevent content-type sniffing attacks.
    return "File download is disabled for security reasons.", 403

if __name__ == "__main__":
    app.run(debug=False, host='0.0.0.0', port=5000)

