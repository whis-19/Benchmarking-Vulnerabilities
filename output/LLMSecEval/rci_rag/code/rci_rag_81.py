import os
from flask import Flask, request, redirect, url_for
from werkzeug.utils import secure_filename
import logging
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import configparser  # For reading configuration files

# Load configuration from file
config = configparser.ConfigParser()
config.read('config.ini')  # Create a config.ini file with your settings

# Configure logging
LOG_LEVEL = config.get('DEFAULT', 'LOG_LEVEL', fallback='INFO').upper()
logging.basicConfig(level=getattr(logging, LOG_LEVEL), format='%(asctime)s - %(levelname)s - %(message)s')

UPLOAD_FOLDER = config.get('DEFAULT', 'UPLOAD_FOLDER', fallback='/path/to/your/secure/uploads')  # Store outside web document root
ALLOWED_EXTENSIONS = set(config.get('DEFAULT', 'ALLOWED_EXTENSIONS', fallback='pdf').split(','))
MAX_FILE_SIZE = config.getint('DEFAULT', 'MAX_FILE_SIZE', fallback=16 * 1024 * 1024)  # 16MB

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_FILE_SIZE  # Limit file size

limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=[config.get('LIMITER', 'DEFAULT_LIMITS', fallback="200 per day, 50 per hour")]  # Example limits
)

# Ensure the upload folder exists and has appropriate permissions
if not os.path.exists(UPLOAD_FOLDER):
    try:
        os.makedirs(UPLOAD_FOLDER, mode=0o700)  # Only owner can read/write/execute
    except OSError as e:
        logging.error(f"Failed to create upload directory: {e}")
        # Handle the error appropriately, e.g., exit the application
        exit() # Exit if we can't create the directory

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS if '.' in filename else False

@app.route('/', methods=['GET', 'POST'])
@limiter.limit(config.get('LIMITER', 'UPLOAD_LIMIT', fallback="5 per minute"))  # Limit uploads to 5 per minute
# TODO: Implement user authentication and session management
def upload_file():
    if request.method == 'POST':
        # check if the post request has the file part
        if 'file' not in request.files:
            logging.warning('No file part')
            return redirect(request.url)
        file = request.files['file']
        # If the user does not select a file, the browser submits an
        # empty file without a filename.
        if file.filename == '':
            logging.warning('No file selected')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)  # Sanitize filename

            # Additional validation:  Check for path traversal attempts *after* secure_filename
            # secure_filename primarily focuses on making the filename safe for the filesystem
            # and doesn't guarantee protection against all path traversal attempts.
            if filename.startswith('.') or '..' in filename or '/' in filename or '\\' in filename:
                logging.warning(f"Invalid filename detected: {filename}")
                return "Invalid filename", 400  # Or a more user-friendly error page

            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)

            # Double check that the final path is within the allowed directory
            if not os.path.abspath(filepath).startswith(os.path.abspath(app.config['UPLOAD_FOLDER'])):
                logging.error(f"Attempted path traversal: {filepath}")
                return "Invalid filename", 400

            try:
                file.save(filepath)
                logging.info(f"File saved successfully: {filepath}")

                # TODO: Implement virus scanning here (e.g., using ClamAV)
                # Example:
                # result = scan_file(filepath)
                # if result['infected']:
                #     logging.warning(f"Virus detected in {filepath}")
                #     os.remove(filepath)  # Remove infected file
                #     return "Virus detected. Upload rejected.", 400

                return 'File uploaded successfully'
            except IOError as e:
                logging.error(f"Disk full or other I/O error: {e}")
                return "Disk full or other I/O error. Please try again later.", 500 # User-friendly message
            except PermissionError as e:
                logging.error(f"Permission error saving file: {e}")
                return "Permission error. Please contact the administrator.", 500 # User-friendly message
            except Exception as e:
                logging.error(f"Error saving file: {e}")
                # In a production environment, provide a user-friendly message
                return "An error occurred while uploading the file. Please try again later.", 500
        else:
            logging.warning(f"Invalid file type uploaded: {file.filename}")
            return 'Invalid file type. Only PDF files are allowed.', 400
    return '''
    <!doctype html>
    <html>
    <head>
        <title>Upload new File</title>
        <meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'none'; object-src 'none'; base-uri 'none'; form-action 'self'; upgrade-insecure-requests;">
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

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)

