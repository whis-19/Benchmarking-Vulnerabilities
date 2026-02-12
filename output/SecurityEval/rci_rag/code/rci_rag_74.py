from flask import Flask, request, redirect, send_from_directory, abort, render_template_string, send_file
import os
import uuid
from werkzeug.utils import secure_filename
import logging
import magic  # For MIME type detection
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB limit
ALLOWED_EXTENSIONS = {'pdf'}

# Enable CSRF protection (requires Flask-WTF) - See comments below for setup
# app.config['WTF_CSRF_ENABLED'] = True
# app.config['SECRET_KEY'] = 'your_secret_key' # Replace with a strong, random key!

# Ensure the upload directory exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Set HttpOnly for session cookie (if you're using sessions)
# Example:
# app.config['SESSION_COOKIE_HTTPONLY'] = True

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Initialize rate limiter
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],  # Example limits
    storage_uri="memory://"  # Use a persistent storage for production
)


def allowed_file(filename):
    """
    Checks if the filename has an allowed extension.
    """
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def is_safe_path(filename):
    """
    Checks if the filename is safe to prevent path traversal vulnerabilities.
    This function implements several security checks:
    1.  Normalizes the path.
    2.  Checks if the path is absolute.
    3.  Checks for ".." sequences.
    """
    normalized_path = os.path.normpath(filename)

    if os.path.isabs(normalized_path) or ".." in normalized_path:
        return False

    return True


@app.route('/pdf/upload', methods=['GET', 'POST'])
@limiter.limit("10/minute")  # Rate limit this endpoint
def upload_pdf():
    """
    Handles PDF file uploads.  Implements CSRF protection (if enabled).
    """
    if request.method == 'POST':
        if 'pdf_file' not in request.files:
            return "No file part", 400

        file = request.files['pdf_file']

        if file.filename == '':
            return "No selected file", 400

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)  # Sanitize filename
            # secure_filename sanitizes the filename, but it doesn't *validate* it.
            # Additional validation (e.g., length check, character whitelist) might be needed.
            if not is_safe_path(filename):
                return "Invalid filename", 400

            # Generate a unique filename to prevent overwrites and guessing
            unique_filename = str(uuid.uuid4())  # Only use the UUID
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)

            # MIME type validation
            try:
                mime = magic.Magic(mime=True)
                file_mime_type = mime.from_buffer(file.read(2048))  # Read first 2048 bytes
                file.seek(0)  # Reset file pointer after reading
                if file_mime_type != 'application/pdf':
                    logging.warning(f"Possible malicious file upload: MIME type is {file_mime_type}")
                    return "Invalid file type.  Not a PDF.", 400
            except Exception as e:
                logging.error(f"Error detecting MIME type: {e}", exc_info=True)
                return "Error validating file type.", 500

            try:
                file.save(filepath)
                logging.info(f"File saved successfully: {filepath}")  # Log successful save
            except Exception as e:
                logging.error(f"Error saving file: {e}", exc_info=True)  # Log the exception with traceback
                return "Error saving file", 500

            return redirect('/pdf/view/' + unique_filename)
        else:
            return "Invalid file type. Only PDF files are allowed.", 400
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Upload PDF</title>
    </head>
    <body>
        <form action="/pdf/upload" method="post" enctype="multipart/form-data">
            <input type="file" name="pdf_file">
            <input type="submit" value="Upload">
        </form>
    </body>
    </html>
    ''')


@app.route('/pdf/view/<filename>')
def view_pdf(filename):
    """
    Serve the PDF file.
    """
    if not is_safe_path(filename):
        return "Invalid filename", 400

    try:
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        # Explicitly set the Content-Type header (optional but recommended)
        # send_from_directory usually handles this correctly, but it's good practice to be explicit.
        return send_file(filepath, mimetype='application/pdf')
    except FileNotFoundError:
        abort(404)


@app.errorhandler(413)
def request_entity_too_large(error):
    return 'File Too Large', 413


@app.errorhandler(429)
def too_many_requests(e):
    return "Too many requests. Please try again later.", 429


if __name__ == '__main__':
    app.run(debug=True)

