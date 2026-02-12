import os
from flask import Flask, request, redirect, url_for, send_from_directory
from werkzeug.utils import secure_filename
import logging

# Configuration
UPLOAD_FOLDER = '/path/to/secure/uploads'  # Store outside web document root
ALLOWED_EXTENSIONS = {'pdf'}  # Only allow PDF files
MAX_FILE_SIZE = 16 * 1024 * 1024  # 16MB limit

# Ensure the upload folder exists and has appropriate permissions
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
# On Linux/Unix:  `chmod 700 /path/to/secure/uploads`  (owner only access)
# On Windows:  Use appropriate ACLs to restrict access.

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_FILE_SIZE  # Protect against large uploads

# Logging setup (important for security auditing)
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')


def allowed_file(filename):
    """Checks if the file extension is allowed."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def is_safe_path(filename):
    """
    Validates the filename to prevent path traversal vulnerabilities.
    Uses werkzeug.utils.secure_filename and additional checks.
    """
    filename = secure_filename(filename)  # Sanitize filename

    if filename is None or filename == "":
        return False  # Reject empty or invalid filenames

    if ".." in filename:
        logging.warning(f"Rejected filename due to '..' sequence: {filename}")
        return False  # Reject filenames with ".."

    if "/" in filename or "\\" in filename:
        logging.warning(f"Rejected filename due to path separators: {filename}")
        return False  # Reject filenames with path separators

    if filename.count(".") > 1:
        logging.warning(f"Rejected filename due to multiple dots: {filename}")
        return False # Reject filenames with multiple dots

    return True


@app.route('/', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        # Check if the post request has the file part
        if 'file' not in request.files:
            logging.warning("No file part in the request")
            return 'No file part', 400

        file = request.files['file']

        # If the user does not select a file, the browser submits an
        # empty file without a filename.
        if file.filename == '':
            logging.warning("No file selected")
            return 'No file selected', 400

        if file and allowed_file(file.filename):
            filename = file.filename  # Get the original filename
            if not is_safe_path(filename):
                return 'Invalid filename', 400

            # Securely construct the full file path
            filename = secure_filename(filename) # Sanitize again after checks
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)

            try:
                file.save(filepath)
                logging.info(f"File saved successfully: {filepath}")
                return 'File uploaded successfully'
            except Exception as e:
                logging.exception(f"Error saving file: {e}")
                return 'Error saving file', 500
        else:
            logging.warning(f"Invalid file type: {file.filename}")
            return 'Invalid file type. Only PDF files are allowed.', 400

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


@app.route('/uploads/<name>')
def download_file(name):
    """
    Serves files from the upload directory.  This route should be protected
    with authentication and authorization in a real application.
    """
    return send_from_directory(app.config["UPLOAD_FOLDER"], name)


if __name__ == "__main__":
    #  DO NOT USE `debug=True` IN PRODUCTION!  It can expose sensitive information.
    app.run(debug=False, host='0.0.0.0', port=5000)

