import os
import uuid
from flask import Flask, request, render_template, send_from_directory
from werkzeug.utils import secure_filename
import logging
import html

app = Flask(__name__)

# Configure logging (important for debugging and security monitoring)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Configuration
UPLOAD_FOLDER = os.path.join(os.getcwd(), 'uploads')  # Store uploads outside web root
ALLOWED_EXTENSIONS = {'pdf'}  # Only allow PDF files
MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # Limit file size to 16MB

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH

# Ensure upload folder exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


def allowed_file(filename):
    """Check if the file extension is allowed."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/', methods=['GET', 'POST'])
def upload_file():
    """Handles file uploads and displays a success/error message."""
    if request.method == 'POST':
        # Check if the post request has the file part
        if 'file' not in request.files:
            logging.warning("No file part in the request")
            return render_template('upload.html', message='No file part')

        file = request.files['file']

        # If the user does not select a file, the browser submits an
        # empty file without a filename.
        if file.filename == '':
            logging.warning("No file selected")
            return render_template('upload.html', message='No file selected')

        if file and allowed_file(file.filename):
            try:
                # Secure filename and prevent path traversal
                filename = secure_filename(file.filename)
                if '..' in filename:
                    logging.warning("Invalid filename with path traversal attempt: %s", filename)
                    return render_template('upload.html', message='Invalid filename')

                # Generate a unique filename to prevent overwrites
                unique_filename = str(uuid.uuid4()) + "_" + filename
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)

                # Save the file
                file.save(filepath)
                logging.info("File saved successfully: %s", filepath)

                # Sanitize the filename for display in the HTML (encode special characters)
                display_filename = html.escape(filename)

                return render_template('upload.html', message=f'File "{display_filename}" uploaded successfully!')

            except Exception as e:
                logging.exception("Error during file upload: %s", e)
                return render_template('upload.html', message=f'An error occurred: {str(e)}')

        else:
            logging.warning("Invalid file type")
            return render_template('upload.html', message='Invalid file type. Only PDF files are allowed.')

    return render_template('upload.html', message='')


@app.route('/uploads/<filename>')
def download_file(filename):
    """Serves uploaded files (with security considerations)."""
    # This route is intentionally left out to prevent direct access to uploaded files.
    # If you need to serve files, implement proper authentication and authorization.
    # Also, consider using a dedicated file server for static content.
    return "Access Denied", 403


@app.errorhandler(413)
def request_entity_too_large(e):
    """Handles file size limit errors."""
    logging.warning("File size exceeded the limit")
    return render_template('upload.html', message='File size exceeds the limit (16MB).'), 413


@app.after_request
def add_header(response):
    """
    Add security headers to every response.
    """
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Content-Security-Policy'] = "default-src 'self'"  # Adjust as needed
    return response


if __name__ == '__main__':
    # Never run with debug=True in production!
    app.run(debug=False, host='0.0.0.0', port=5000)

