import os
import secrets
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, send_from_directory
from werkzeug.utils import secure_filename
import logging

app = Flask(__name__)
app.secret_key = secrets.token_hex(24)  # Change this to a strong, random key
UPLOAD_FOLDER = 'uploads'  # Store uploads outside the web document root
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}  # Allowlist of file extensions
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB limit

# Ensure the upload folder exists and has appropriate permissions
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.chmod(UPLOAD_FOLDER, 0o700)  # Restrict access to the owner

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# CSP Header
@app.after_request
def add_csp_header(response):
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none';"
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response

# CSRF protection
def generate_csrf_token():
    session['csrf_token'] = secrets.token_hex(16)
    return session['csrf_token']

def validate_csrf_token(token):
    return 'csrf_token' in session and session['csrf_token'] == token

def csrf_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.method == 'POST':
            token = request.form.get('csrf_token')
            if not token or not validate_csrf_token(token):
                logging.warning("CSRF token validation failed.")
                return render_template('error.html', message="CSRF token is invalid."), 400
        return f(*args, **kwargs)
    return decorated_function

app.jinja_env.globals['csrf_token'] = generate_csrf_token

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def sanitize_filename(filename):
    """Sanitizes a filename to prevent directory traversal and other attacks."""
    if not filename:
        return None

    filename = secure_filename(filename)  # Basic sanitization

    if filename.count("..") > 0:
        logging.warning(f"Filename contains '..' sequence: {filename}")
        return None

    if "/" in filename or "\\" in filename:
        logging.warning(f"Filename contains path separators: {filename}")
        return None

    if filename.startswith("."):
        logging.warning(f"Filename starts with '.': {filename}")
        return None

    if len(filename) > 255: # Limit filename length
        logging.warning(f"Filename too long: {filename}")
        return None

    return filename

def validate_filepath(filepath):
    """Validates a filepath against an allowlist and prevents traversal."""

    if not filepath:
        return False

    if "/" in filepath or "\\" in filepath:
        logging.warning(f"Filepath contains path separators: {filepath}")
        return False

    if ".." in filepath:
        logging.warning(f"Filepath contains '..' sequence: {filepath}")
        return False

    if filepath.startswith("."):
        logging.warning(f"Filepath starts with '.': {filepath}")
        return False

    # Example allowlist (adapt to your needs)
    allowed_filepaths = ["profile_pictures", "documents"]
    if filepath not in allowed_filepaths:
        logging.warning(f"Filepath not in allowlist: {filepath}")
        return False

    return True

@app.route('/', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        # Validate CSRF token
        csrf_token = request.form.get('csrf_token')
        if not validate_csrf_token(csrf_token):
            logging.warning("CSRF token validation failed.")
            return render_template('error.html', message="CSRF token is invalid."), 400

        # Check if the post request has the file part
        if 'file' not in request.files:
            logging.warning("No file part in the request.")
            return render_template('error.html', message='No file part'), 400
        file = request.files['file']

        # If the user does not select a file, the browser submits an
        # empty file without a filename.
        if file.filename == '':
            logging.warning("No file selected.")
            return render_template('error.html', message='No selected file'), 400

        if file and allowed_file(file.filename):
            filename = sanitize_filename(file.filename)
            if not filename:
                return render_template('error.html', message='Invalid filename'), 400

            # Example of validating a user-provided filepath (adapt to your needs)
            user_filepath = request.form.get('filepath')
            if not user_filepath:
                return render_template('error.html', message='Filepath is required'), 400

            if not validate_filepath(user_filepath):
                return render_template('error.html', message='Invalid filepath'), 400

            filepath = os.path.join(UPLOAD_FOLDER, user_filepath)
            os.makedirs(filepath, exist_ok=True) # Ensure the subdirectory exists

            full_filename = os.path.join(filepath, filename)

            try:
                # Check file size before saving
                file.seek(0, os.SEEK_END)
                file_length = file.tell()
                file.seek(0)  # Reset file pointer to the beginning

                if file_length > MAX_FILE_SIZE:
                    logging.warning(f"File size exceeds the limit: {file_length} bytes")
                    return render_template('error.html', message=f'File size exceeds the limit of {MAX_FILE_SIZE // (1024 * 1024)} MB'), 400

                file.save(full_filename)
                logging.info(f"File saved successfully: {full_filename}")
                return render_template('success.html', filename=filename)

            except Exception as e:
                logging.exception(f"Error saving file: {e}")
                return render_template('error.html', message=f'Error saving file: {e}'), 500
        else:
            logging.warning(f"Invalid file extension: {file.filename}")
            return render_template('error.html', message='Invalid file type. Allowed types: ' + ', '.join(ALLOWED_EXTENSIONS)), 400

    return render_template('upload.html')

@app.route('/uploads/<path:filename>')
def download_file(filename):
    """Serve files from the upload directory."""
    # Basic filename sanitization (double check)
    if ".." in filename:
        logging.warning(f"Attempted path traversal: {filename}")
        return "Access Denied", 403

    try:
        return send_from_directory(UPLOAD_FOLDER, filename, as_attachment=True)
    except FileNotFoundError:
        logging.warning(f"File not found: {filename}")
        return "File Not Found", 404

@app.errorhandler(404)
def page_not_found(e):
    return render_template('error.html', message="Page not found"), 404

@app.errorhandler(500)
def internal_server_error(e):
    logging.exception("Internal Server Error")
    return render_template('error.html', message="Internal server error"), 500

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)

